# -*- test-case-name: twisted.conch.test.test_service_ledger -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
A host-facing settlement ledger for the SSH transport, the I{ssh-connection}
service and the I{ssh-userauth} service.

The three SSH layers settle their work on completion planes which are kept
deliberately separate:

    1. the transport's key-exchange blocked queue is either I{flushed} in
       enqueue order once I{MSG_NEWKEYS} arrives, or I{voided} when the
       connection is torn down before the exchange finishes,
    2. L{twisted.conch.ssh.connection.SSHConnection.serviceStopped} settles
       fully open channels (C{channelClosed}, pending request deferreds fail
       with C{ConchError("Channel closed.")}), channels still opening
       (C{openFailed(ConnectionLost)}), and global requests
       (C{ConchError("Connection stopped.")}), and
    3. L{twisted.conch.ssh.userauth.SSHUserAuthServer.serviceStopped} settles
       the login-timeout L{DelayedCall} by cancellation, while the timeout
       firing settles it by disconnecting.

A single L{ServiceLedger} is installed on one transport (and therefore shared
by that transport's services) with L{ServiceLedger.enableServiceLedger}.  It
records every settled outcome so that work which is still running nested
inside an already-committed outer settlement cannot write through the order,
terminal channel state, L{Deferred} failure type, or timeout-handle fate the
outer settlement already committed:

    - a blocked queue which was flushed stays flushed in the exact committed
      wire order, and a queue which was voided is detached so that later
      (inner) enqueues can never ride a flush that will not happen,
    - a channel/global request which already received its terminal failure
      keeps exactly that failure, and a second C{serviceStopped} is a no-op,
    - a login-timeout handle committed as cancelled never fires its
      disconnect, just as a handle which fired is never cancelled.

Every hook here is a one-way commit: the ledger only grows records, it never
undoes a side effect that was already observed on the wire, on a channel, on
a L{Deferred}, or on a L{DelayedCall}.
"""

from __future__ import annotations

from typing import Any

# Fates a single key-exchange round's blocked queue can settle into.
KEX_QUEUE_FLUSHED = "flushed"
KEX_QUEUE_VOIDED = "voided"

# Fates a single login-timeout DelayedCall can settle into.
LOGIN_TIMEOUT_PENDING = "pending"
LOGIN_TIMEOUT_CANCELLED = "cancelled"
LOGIN_TIMEOUT_FIRED = "fired"


_UNSET = object()


class _KeyExchangeRound:
    """
    The blocked-queue settlement record for one key exchange (including
    rekeys).

    @ivar index: Zero-based position of this round on the transport.
    @ivar fate: C{None} while the exchange is open, otherwise
        L{KEX_QUEUE_FLUSHED} or L{KEX_QUEUE_VOIDED}.
    @ivar flushed: The C{(messageType, payload)} entries committed to the
        wire in order, once the round was flushed.
    @ivar voided: The entries dropped without ever being sent, once the
        round was voided.
    @ivar refused: Entries an inner sender tried to push into the queue
        after the round had already been voided; never sent.
    """

    def __init__(self, index: int) -> None:
        self.index = index
        self.fate: str | None = None
        self.flushed: tuple[tuple[int, bytes], ...] = ()
        self.voided: tuple[tuple[int, bytes], ...] = ()
        self.refused: list[tuple[int, bytes]] = []


def _observeFailure(deferred, sink: list) -> None:
    """
    Attach a pass-through errback to C{deferred} which records the settled
    exception value in C{sink}, then re-propagates the L{Failure} so every
    later observer still sees the real terminal failure.
    """

    def _record(failure):
        sink.append(failure.value)
        return failure

    deferred.addErrback(_record)


class ServiceLedger:
    """
    Host-facing record of the settlements committed by one SSH transport and
    its services.

    All attributes are append-only observations; there is deliberately no
    method to revoke or roll a settlement back.

    @ivar keyExchangeRounds: L{_KeyExchangeRound} records in opening order.
    @ivar connectionLostReason: The reason the first C{connectionLost}
        committed, or the C{_UNSET} sentinel while the connection is alive.
    @ivar loggedOut: C{True} once the avatar logout of a full connection
        loss ran.
    @ivar serviceSwitches: C{(oldService, newService)} pairs committed by
        C{setService}; a switch never performs an avatar logout.
    @ivar stoppedConnections: The connection-service instances whose
        C{serviceStopped} committed, in order.
    @ivar closedChannels: Channels settled through C{channelClosed}.
    @ivar closedChannelFailures: Exception values observed on the pending
        request deferreds of closed channels.
    @ivar openFailedChannels: C{(channel, reason)} pairs settled through
        C{openFailed}.
    @ivar failedGlobalRequests: The global-request deferreds which were
        errbacked with C{ConchError("Connection stopped.")}.
    @ivar globalRequestFailures: The observed exception values of those
        global-request deferreds, in errback order.
    @ivar scheduledLoginTimeouts: Login-timeout L{DelayedCall}s scheduled.
    @ivar cancelledLoginTimeouts: L{DelayedCall}s settled by cancellation.
    @ivar firedLoginTimeouts: L{DelayedCall}s settled by firing.
    """

    def __init__(self) -> None:
        self.keyExchangeRounds: list[_KeyExchangeRound] = []
        self.connectionLostReason: Any = _UNSET
        self.loggedOut = False
        self.serviceSwitches: list[tuple[object, object]] = []

        self.stoppedConnections: list[object] = []
        self.closedChannels: list[object] = []
        self.closedChannelFailures: list[BaseException] = []
        self.openFailedChannels: list[tuple[object, BaseException]] = []
        self.failedGlobalRequests: list[object] = []
        self.globalRequestFailures: list[BaseException] = []

        self.scheduledLoginTimeouts: list[object] = []
        self.cancelledLoginTimeouts: list[object] = []
        self.firedLoginTimeouts: list[object] = []

        self._closedChannelSettlements: set[tuple[int, int]] = set()
        self._openFailedSettlements: set[tuple[int, int]] = set()
        self._loginTimeoutFate: dict[int, str] = {}
        self._latestLoginTimeout: dict[int, object] = {}

    # ------------------------------------------------------------------
    # Carrier 1: transport blocked queue, flush and void
    # ------------------------------------------------------------------

    def keyExchangeRoundBegan(self, host: object) -> _KeyExchangeRound:
        """
        Record that a new key exchange (or rekey) opened a fresh blocked
        queue on C{host}.
        """
        round = _KeyExchangeRound(len(self.keyExchangeRounds))
        self.keyExchangeRounds.append(round)
        return round

    def _activeRound(self) -> _KeyExchangeRound | None:
        if self.keyExchangeRounds:
            round = self.keyExchangeRounds[-1]
            if round.fate is None:
                return round
        return None

    def flushKeyExchangeQueue(self, host: object) -> bool:
        """
        Commit the I{NEWKEYS} exit: adopt the blocked queue snapshot as the
        committed wire order and resend each entry through C{host.sendPacket}.

        Snapshotting is the commit boundary: entries an inner sender appends
        to the old queue object while the flush is running cannot ride this
        flush.  If the round was already voided (the disconnect exit
        committed first) nothing is replayed.

        @return: C{True} if this call performed the flush, C{False} if an
            earlier void settlement won.
        """
        round = self._activeRound()
        blocked = getattr(host, "_blockedByKeyExchange", None)
        host._blockedByKeyExchange = None
        if round is None:
            # Ledger installed between exchanges, or an already settled
            # round: nothing recorded, but any pending entries must still
            # honour NEWKEYS ordering.
            if blocked is not None and not (
                self.keyExchangeRounds
                and self.keyExchangeRounds[-1].fate == KEX_QUEUE_VOIDED
            ):
                for messageType, payload in tuple(blocked):
                    host.sendPacket(messageType, payload)
                return True
            return False
        if round.fate == KEX_QUEUE_VOIDED:
            return False
        snapshot = tuple(blocked or ())
        round.fate = KEX_QUEUE_FLUSHED
        round.flushed = snapshot
        for messageType, payload in snapshot:
            host.sendPacket(messageType, payload)
        return True

    def voidKeyExchangeQueue(self, host: object) -> tuple[tuple[int, bytes], ...]:
        """
        Commit the disconnect-before-NEWKEYS exit: detach the blocked queue
        so it can never be flushed or appended to again, and record its
        entries as voided.

        A round already flushed keeps that fate: bytes on the wire cannot be
        un-sent.

        @return: The entries that were dropped without being sent.
        """
        round = self._activeRound()
        blocked = getattr(host, "_blockedByKeyExchange", None)
        entries = tuple(blocked or ())
        host._blockedByKeyExchange = None
        if round is not None and round.fate is None:
            round.fate = KEX_QUEUE_VOIDED
            round.voided = entries
        return entries

    def keyExchangeMessageRefused(
        self, host: object, messageType: int, payload: bytes
    ) -> None:
        """
        Record an inner attempt to queue C{messageType} after the active
        round had already been voided.  The message is refused every exit:
        it never reaches the wire.
        """
        round = self._activeRound()
        if round is None and self.keyExchangeRounds:
            round = self.keyExchangeRounds[-1]
        if round is not None:
            round.refused.append((messageType, payload))

    # ------------------------------------------------------------------
    # Carrier 1 boundary: full connection loss vs. service switch
    # ------------------------------------------------------------------

    def transportConnectionLostBegan(self, host: object, reason: object) -> bool:
        """
        Commit the full-connection-loss exit (distinct from a service
        switch): void any blocked queue, remember C{reason}, and authorize
        the service stop plus avatar logout.  A nested or repeated call is a
        no-op so the current service and the avatar are never settled twice.

        @return: C{True} only for the first loss of this connection.
        """
        if self.connectionLostReason is not _UNSET:
            return False
        self.voidKeyExchangeQueue(host)
        self.connectionLostReason = reason
        return True

    def transportAvatarLoggedOut(self) -> None:
        """
        Record that the avatar logout which belongs to a full connection
        loss ran.  A service switch never reaches this hook.
        """
        self.loggedOut = True

    def transportServiceSwitched(
        self, host: object, oldService: object, newService: object
    ) -> None:
        """
        Record the service-switch exit: the old service is stopped and the
        new one started without an avatar logout.
        """
        self.serviceSwitches.append((oldService, newService))

    # ------------------------------------------------------------------
    # Carrier 2: ssh-connection channels and global requests
    # ------------------------------------------------------------------

    def connectionServiceCanStop(self, conn: object) -> bool:
        """
        Commit C{serviceStopped} for C{conn} exactly once.

        @return: C{True} for the first stop (the caller runs the three
            terminal settlements), C{False} for a nested or repeated stop.
        """
        if conn in self.stoppedConnections:
            return False
        self.stoppedConnections.append(conn)
        return True

    def isConnectionServiceStopped(self, conn: object) -> bool:
        """
        @return: C{True} once C{conn} has committed its service stop.  Inner
            work started afterwards must reuse the already-committed failure
            forms instead of escaping the settlement.
        """
        return conn in self.stoppedConnections

    def channelSettledClosed(
        self, conn: object, channel: object, pendingDeferreds: list
    ) -> None:
        """
        Record the open-channel exit: C{channel} is being closed and each
        deferred in C{pendingDeferreds} is about to fail with
        C{ConchError("Channel closed.")}.  The real failures are observed
        pass-through, never swallowed.
        """
        key = (id(conn), id(channel))
        if key in self._closedChannelSettlements:
            return
        self._closedChannelSettlements.add(key)
        self.closedChannels.append(channel)
        for deferred in pendingDeferreds:
            _observeFailure(deferred, self.closedChannelFailures)

    def channelSettledOpenFailed(
        self, conn: object, channel: object, reason: BaseException
    ) -> bool:
        """
        Record the still-opening-channel exit: C{channel} is about to receive
        C{openFailed(reason)} (L{ConnectionLost} on service stop).

        @return: C{False} if this channel already has an open-failed
            settlement, so it is never failed twice.
        """
        key = (id(conn), id(channel))
        if key in self._openFailedSettlements:
            return False
        self._openFailedSettlements.add(key)
        self.openFailedChannels.append((channel, reason))
        return True

    def globalRequestsSettled(self, conn: object, deferreds: list) -> None:
        """
        Record the batch global-request exit performed by C{serviceStopped}:
        each deferred is about to fail with C{ConchError("Connection
        stopped.")}.
        """
        for deferred in deferreds:
            if deferred in self.failedGlobalRequests:
                continue
            self.failedGlobalRequests.append(deferred)
            _observeFailure(deferred, self.globalRequestFailures)

    def globalRequestSettled(self, conn: object, deferred: object) -> None:
        """
        Record a single global request created by an inner sender after the
        stop committed; it receives the same C{Connection stopped.} failure.
        """
        if deferred not in self.failedGlobalRequests:
            self.failedGlobalRequests.append(deferred)
            _observeFailure(deferred, self.globalRequestFailures)

    # ------------------------------------------------------------------
    # Carrier 3: ssh-userauth login timeout
    # ------------------------------------------------------------------

    def loginTimeoutScheduled(self, auth: object, delayedCall: object) -> None:
        """
        Record that C{auth} scheduled C{delayedCall} as its login-timeout
        handle.
        """
        self._loginTimeoutFate[id(delayedCall)] = LOGIN_TIMEOUT_PENDING
        self._latestLoginTimeout[id(auth)] = delayedCall
        self.scheduledLoginTimeouts.append(delayedCall)

    def loginTimeoutCancelCommitted(self, auth: object, delayedCall: object) -> bool:
        """
        Commit the service-stop exit for the login timeout: its handle is
        cancelled before firing.  A handle whose firing already committed
        cannot be retroactively cancelled.

        @return: C{True} if cancellation is the winning settlement.
        """
        fate = self._loginTimeoutFate.get(id(delayedCall))
        if fate == LOGIN_TIMEOUT_FIRED:
            return False
        if fate is None:
            self._latestLoginTimeout[id(auth)] = delayedCall
        self._loginTimeoutFate[id(delayedCall)] = LOGIN_TIMEOUT_CANCELLED
        self.cancelledLoginTimeouts.append(delayedCall)
        return True

    def loginTimeoutFireCommitted(
        self, auth: object, delayedCall: object | None
    ) -> bool:
        """
        Commit the timeout exit: the handle fired and may now disconnect.

        C{delayedCall} may be C{None} when an inner caller reaches this hook
        after an earlier stop cleared the handle; the fate of that service's
        latest scheduled handle is then consulted so a committed cancellation
        is never rewritten as a timeout disconnect.

        @return: C{True} if firing is the winning settlement, C{False} if the
            timeout was already cancelled or already fired.
        """
        if delayedCall is None:
            delayedCall = self._latestLoginTimeout.get(id(auth))
        if delayedCall is None:
            return True
        fate = self._loginTimeoutFate.get(id(delayedCall))
        if fate in (LOGIN_TIMEOUT_CANCELLED, LOGIN_TIMEOUT_FIRED):
            return False
        self._loginTimeoutFate[id(delayedCall)] = LOGIN_TIMEOUT_FIRED
        self.firedLoginTimeouts.append(delayedCall)
        return True
