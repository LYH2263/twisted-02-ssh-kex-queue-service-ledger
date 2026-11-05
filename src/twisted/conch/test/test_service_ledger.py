# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for the host-facing SSH service settlement ledger.

Every scenario here advances nested outer/inner work on the SAME reactor
clock and transport instance (never two unrelated reactors): the outer
settlement commits first, and work that is still running inside it must not
write through the packet order, channel terminal state, L{Deferred} failure
types, or login-timeout handle fate the outer settlement already observed.

The three carriers are tested independently:

    1. transport blocked-queue flush (C{MSG_NEWKEYS}) versus void
       (C{sendDisconnect}/C{loseConnection} before the exchange finishes),
       and the full C{connectionLost} settlement versus C{setService},
    2. L{SSHConnection.serviceStopped} terminal forms for fully open
       channels, channels still opening, and global requests,
    3. L{SSHUserAuthServer.serviceStopped} login-timeout cancellation
       versus the timeout firing.

Terminal state is always observed on the real artifacts: bytes actually
written to the wire, the callbacks the channels received, the L{Failure}s
the deferreds fired with, and whether the L{DelayedCall} is still pending.
"""

import struct

from twisted.conch import error
from twisted.conch.ssh import _service_ledger, common, connection, transport, userauth
from twisted.conch.test import test_connection, test_transport, test_userauth
from twisted.cred.portal import Portal
from twisted.internet import defer, task
from twisted.internet.error import ConnectionLost
from twisted.python.reflect import requireModule
from twisted.test import proto_helpers
from twisted.trial import unittest

cryptography = requireModule("cryptography")

MockTransportBase = test_transport.MockTransportBase
MockCipher = test_transport.MockCipher
MockService = test_transport.MockService
TestConnection = test_connection.TestConnection
TestChannel = test_connection.TestChannel
TestAvatar = test_connection.TestAvatar
FakeTransport = test_userauth.FakeTransport
Realm = test_userauth.Realm
PasswordChecker = test_userauth.PasswordChecker


def _message(exc):
    """
    The SSH error message carried by a L{twisted.conch.error.ConchError}
    (its first constructor value, since its L{str} includes the data tuple).
    """
    return exc.value


# ---------------------------------------------------------------------------
# Carrier 1: transport blocked queue flush / void and loss / switch boundary
# ---------------------------------------------------------------------------


class TransportKeyExchangeLedgerTests(unittest.TestCase):
    if not cryptography:
        skip = "Cannot run without cryptography"

    def setUp(self):
        self.wire = proto_helpers.StringTransport()
        self.proto = MockTransportBase()
        # The ledger is installed before the transport ever connects, so the
        # initial key exchange opens a tracked round.
        self.ledger = self.proto.enableServiceLedger()
        self.assertIsNotNone(self.ledger)
        self.proto.makeConnection(self.wire)
        # Exchange the peer KEXINIT: the round moves REQUESTED -> PROGRESSING
        # and negotiation fills the compression/encryption slots, as in a
        # real exchange.
        self.proto.dataReceived(b"SSH-2.0-BogoClient-1.2i\r\n")
        self.proto.dispatchMessage(
            transport.MSG_KEXINIT,
            test_transport.BaseSSHTransportTests._A_KEXINIT_MESSAGE,
        )
        # Keep flushed packets inspectable on the wire instead of encrypting
        # them, mirroring the existing key-exchange test fixtures.
        self.proto.nextEncryptions = MockCipher()
        self.round = self.ledger.keyExchangeRounds[0]

    def test_ledgerStartsOptInAndRoundTracked(self):
        """
        Enabling is opt-in and the initial exchange opened exactly one live
        round on this transport.
        """
        self.assertEqual(len(self.ledger.keyExchangeRounds), 1)
        self.assertIsNone(self.round.fate)

    def test_allowedMessagesGoDirectWhileOthersQueue(self):
        """
        During one exchange the direct cut and the queue cut are different:
        key-exchange-legal types reach the wire immediately while channel
        class traffic is held, identity and order preserved.
        """
        self.proto.sendPacket(transport.MSG_IGNORE, common.NS(b"direct-cut"))
        self.assertIn(b"direct-cut", self.wire.value())

        self.proto.sendPacket(transport.MSG_SERVICE_REQUEST, common.NS(b"held-one"))
        self.proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"held-two"))
        self.assertNotIn(b"held-one", self.wire.value())
        self.assertNotIn(b"held-two", self.wire.value())
        # Observed by identity, not just by counting the queue.
        self.assertEqual(
            self.proto._blockedByKeyExchange,
            [
                (transport.MSG_SERVICE_REQUEST, common.NS(b"held-one")),
                (connection.MSG_CHANNEL_OPEN, common.NS(b"held-two")),
            ],
        )

    def test_newKeysFlushesQueueInEnqueueOrder(self):
        """
        NEWKEYS commits the flush: held entries reach the wire in their
        enqueue order and the round fate is recorded as flushed.
        """
        self.proto.sendPacket(transport.MSG_SERVICE_REQUEST, common.NS(b"held-one"))
        self.proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"held-two"))
        staleQueue = self.proto._blockedByKeyExchange

        self.proto._newKeys()

        wire = self.wire.value()
        self.assertLess(wire.index(b"held-one"), wire.index(b"held-two"))
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_FLUSHED)
        self.assertEqual(
            self.round.flushed,
            (
                (transport.MSG_SERVICE_REQUEST, common.NS(b"held-one")),
                (connection.MSG_CHANNEL_OPEN, common.NS(b"held-two")),
            ),
        )
        self.assertIsNone(self.proto._blockedByKeyExchange)

        # Inner write-through attempt: an entry appended to the stale queue
        # object after the flush committed must not ride the committed order.
        staleQueue.append((connection.MSG_CHANNEL_OPEN, common.NS(b"late-inner")))
        self.assertNotIn(b"late-inner", self.wire.value())
        # A committed flush is irreversible: its entries stayed on the wire.
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_FLUSHED)

    def test_disconnectVoidsQueueAndLateNewKeysNeverReplays(self):
        """
        When sendDisconnect/loseConnection wins before NEWKEYS, the queued
        entries are voided (dropped, detached) and never replayed by a late
        NEWKEYS or by an inner sender still pushing traffic.
        """
        self.proto.sendPacket(transport.MSG_SERVICE_REQUEST, common.NS(b"queued-one"))
        self.proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"queued-two"))

        self.proto.loseConnection()

        wire = self.wire.value()
        # The disconnect itself is a legal mid-KEX message and went out.
        self.assertIn(b"user closed connection", wire)
        # The held entries did not.
        self.assertNotIn(b"queued-one", wire)
        self.assertNotIn(b"queued-two", wire)
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_VOIDED)
        self.assertEqual(
            self.round.voided,
            (
                (transport.MSG_SERVICE_REQUEST, common.NS(b"queued-one")),
                (connection.MSG_CHANNEL_OPEN, common.NS(b"queued-two")),
            ),
        )
        self.assertIsNone(self.proto._blockedByKeyExchange)

        # Inner sender keeps working during shutdown: its packet is refused
        # every exit rather than re-creating the queue.
        self.proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"inner-void"))
        self.assertNotIn(b"inner-void", self.wire.value())
        self.assertEqual(
            self.round.refused,
            [(connection.MSG_CHANNEL_OPEN, common.NS(b"inner-void"))],
        )

        # A late NEWKEYS (the flush exit) cannot overturn the void fate.
        self.proto._newKeys()
        self.assertNotIn(b"queued-one", self.wire.value())
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_VOIDED)

    def test_rekeyOpensAnIndependentRound(self):
        """
        After the first exchange flushes, a rekey opens a fresh queue whose
        fate is settled independently of the earlier flushed round.
        """
        self.proto._newKeys()
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_FLUSHED)

        self.proto.sendKexInit()
        self.assertEqual(len(self.ledger.keyExchangeRounds), 2)
        rekeyRound = self.ledger.keyExchangeRounds[1]
        self.assertIsNone(rekeyRound.fate)

        self.proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"rekey-held"))
        self.proto.loseConnection()

        self.assertEqual(rekeyRound.fate, _service_ledger.KEX_QUEUE_VOIDED)
        self.assertNotIn(b"rekey-held", self.wire.value())
        # The first round's committed flush is untouched.
        self.assertEqual(self.round.fate, _service_ledger.KEX_QUEUE_FLUSHED)


class TransportSettlementBoundaryTests(unittest.TestCase):
    if not cryptography:
        skip = "Cannot run without cryptography"

    class _ReentrantService(MockService):
        """
        A service whose stop re-enters the transport's C{connectionLost}
        while the outer loss is still settling it.
        """

        def serviceStopped(self):
            MockService.serviceStopped(self)
            self.transport.connectionLost(None)

    def setUp(self):
        self.wire = proto_helpers.StringTransport()
        self.proto = MockTransportBase()
        self.ledger = self.proto.enableServiceLedger()
        self.proto.makeConnection(self.wire)

    def test_serviceSwitchStopsOldStartsNewWithoutLogout(self):
        """
        setService is its own boundary: the old service is stopped and the
        new one started, and no avatar logout is performed by the switch.
        """
        first = MockService()
        second = MockService()
        self.proto.setService(first)
        self.proto.setService(second)

        self.assertTrue(first.stopped)
        self.assertTrue(second.started)
        self.assertIs(self.proto.service, second)
        self.assertEqual(self.ledger.serviceSwitches, [(None, first), (first, second)])
        self.assertIs(self.ledger.connectionLostReason, _service_ledger._UNSET)
        self.assertFalse(self.ledger.loggedOut)

    def test_connectionLostStopsServiceAndLogsOutOnceEvenWhenNested(self):
        """
        Full connection loss is the other boundary: it stops the current
        service and logs out the avatar exactly once, even when service
        stop re-enters connectionLost and loss is reported again afterwards.
        """
        service = self._ReentrantService()
        self.proto.setService(service)
        logouts = []
        self.proto.avatar = object()
        self.proto.logoutFunction = lambda: logouts.append(1)

        self.proto.connectionLost(None)

        self.assertTrue(service.stopped)
        self.assertEqual(logouts, [1])
        self.assertTrue(self.ledger.loggedOut)
        # The committed loss cannot be re-settled by an outer/late report.
        self.proto.connectionLost(None)
        self.assertEqual(logouts, [1])

    def test_serviceSwitchDoesNotLogoutEvenWithAvatar(self):
        """
        A switch performed after an avatar exists still leaves logout to the
        eventual full connection loss only.
        """
        first = MockService()
        second = MockService()
        self.proto.setService(first)
        self.proto.avatar = object()
        self.proto.logoutFunction = lambda: None
        self.proto.setService(second)
        self.assertFalse(self.ledger.loggedOut)
        self.proto.connectionLost(None)
        self.assertTrue(self.ledger.loggedOut)


# ---------------------------------------------------------------------------
# Carrier 2: SSHConnection open / opening / global terminal forms
# ---------------------------------------------------------------------------


class ConnectionServiceLedgerTests(unittest.TestCase):
    if not cryptography:
        skip = "Cannot run without cryptography"

    def setUp(self):
        self.transport = FakeTransport(None)
        self.transport.avatar = TestAvatar()
        self.ledger = self.transport.enableServiceLedger()
        self.conn = TestConnection()
        self.conn.transport = self.transport
        self.conn.serviceStarted()

    def _confirm(self, channel):
        """
        Confirm a channel opened through openChannel, stripping its
        MSG_CHANNEL_OPEN packet like the existing connection fixtures do.
        """
        self.transport.packets = self.transport.packets[:-1]
        self.conn.ssh_CHANNEL_OPEN_CONFIRMATION(
            struct.pack(">2L", channel.id, 255) + b"\x00\x02\x00\x00\x00\x00\x80\x00"
        )

    def test_threeTerminalSettlementsSurviveNestedInnerWork(self):
        """
        Once serviceStopped commits, its three terminal forms are final:
        inner work driven from inside a channel's closed() callback receives
        the same forms, nothing new reaches the wire, and a nested
        serviceStopped is a no-op.
        """
        # One fully open channel with a request still waiting for a reply.
        openChannel = TestChannel()
        self.conn.openChannel(openChannel)
        self._confirm(openChannel)
        channelDeferred = self.conn.sendRequest(openChannel, b"rq", b"", wantReply=1)

        # One channel still in the opening state.
        openingChannel = TestChannel()
        self.conn.openChannel(openingChannel)

        # One global request still waiting for a reply.
        globalDeferred = self.conn.sendGlobalRequest(b"global", b"", wantReply=1)

        # Inner work raced against the committed stop, driven from the open
        # channel's own closed() callback.
        closedCalls = []
        innerChannel = TestChannel()
        innerGlobal = []

        def closedDuringStop():
            closedCalls.append(1)
            TestChannel.closed(openChannel)
            # A channel opened by inner work gets the opening-channel form.
            self.conn.openChannel(innerChannel)
            # A global request from inner work gets the global-request form.
            innerGlobal.append(self.conn.sendGlobalRequest(b"inner", b"", 1))
            # A nested stop must not re-run any settlement.
            self.conn.serviceStopped()

        openChannel.closed = closedDuringStop

        packetsBeforeStop = list(self.transport.packets)
        self.conn.serviceStopped()

        # Nothing the inner work tried reached the wire.
        self.assertEqual(self.transport.packets, packetsBeforeStop)

        # Open-channel exit: closed exactly once, through channelClosed.
        self.assertEqual(closedCalls, [1])
        self.assertTrue(openChannel.gotClosed)
        # Opening-channel exit, both pre-stop and inner: openFailed with
        # ConnectionLost (not a ConchError), never confirmed.
        self.assertIsInstance(openingChannel.openFailureReason, ConnectionLost)
        self.assertIsInstance(innerChannel.openFailureReason, ConnectionLost)
        self.assertFalse(openingChannel.gotOpen)
        self.assertFalse(innerChannel.gotOpen)
        # Nothing escaped the settlement as a live channel.
        self.assertEqual(self.conn.channels, {})
        self.assertEqual(self.conn.channelsToRemoteChannel, {})
        self.assertEqual(self.conn.deferreds["global"], [])

        # A repeated stop after unwinding is still a no-op.
        self.conn.serviceStopped()
        self.assertEqual(closedCalls, [1])

        # Failure TYPES and MESSAGES observed on the real deferreds.
        checks = []
        channelDeferred = self.assertFailure(channelDeferred, error.ConchError)
        channelDeferred.addCallback(
            lambda exc: self.assertEqual(_message(exc), "Channel closed.")
        )
        checks.append(channelDeferred)
        for d in (globalDeferred, innerGlobal[0]):
            d = self.assertFailure(d, error.ConchError)
            d.addCallback(
                lambda exc: self.assertEqual(_message(exc), "Connection stopped.")
            )
            checks.append(d)
        return defer.gatherResults(checks)

    def test_ledgerRecordsTheThreeSettlementSets(self):
        """
        The ledger's recorded sets are distinct for the three exits and the
        observed exception values carry the terminal failure types.
        """
        openChannel = TestChannel()
        self.conn.openChannel(openChannel)
        self._confirm(openChannel)
        channelDeferred = self.conn.sendRequest(openChannel, b"rq", b"", wantReply=1)
        openingChannel = TestChannel()
        self.conn.openChannel(openingChannel)
        globalDeferred = self.conn.sendGlobalRequest(b"global", b"", wantReply=1)

        self.conn.serviceStopped()

        self.assertEqual(self.ledger.closedChannels, [openChannel])
        openFailedChannels = [c for c, _ in self.ledger.openFailedChannels]
        openFailedReasons = [r for _, r in self.ledger.openFailedChannels]
        self.assertEqual(openFailedChannels, [openingChannel])
        self.assertTrue(all(isinstance(r, ConnectionLost) for r in openFailedReasons))
        # The openFailed reason object is the exact one the channel got.
        self.assertIs(
            self.ledger.openFailedChannels[0][1], openingChannel.openFailureReason
        )
        self.assertEqual(self.ledger.failedGlobalRequests, [globalDeferred])
        self.assertEqual(
            [type(e) for e in self.ledger.closedChannelFailures], [error.ConchError]
        )
        self.assertEqual(
            [_message(e) for e in self.ledger.closedChannelFailures],
            ["Channel closed."],
        )
        self.assertEqual(
            [type(e) for e in self.ledger.globalRequestFailures], [error.ConchError]
        )
        self.assertEqual(
            [_message(e) for e in self.ledger.globalRequestFailures],
            ["Connection stopped."],
        )
        checks = [
            self.assertFailure(channelDeferred, error.ConchError),
            self.assertFailure(globalDeferred, error.ConchError),
        ]
        return defer.gatherResults(checks)

    def test_innerWorkAfterStopReusesCommittedForms(self):
        """
        Inner openChannel / sendGlobalRequest calls made after an entirely
        synchronous stop reuse the committed forms instead of hanging or
        escaping with a different failure.
        """
        self.conn.serviceStopped()
        self.assertTrue(self.ledger.isConnectionServiceStopped(self.conn))

        lateChannel = TestChannel()
        self.conn.openChannel(lateChannel)
        self.assertIsInstance(lateChannel.openFailureReason, ConnectionLost)
        self.assertEqual(self.conn.channels, {})

        lateNoReply = self.conn.sendGlobalRequest(b"no-reply", b"", wantReply=0)
        self.assertIsNone(lateNoReply)
        lateReply = self.conn.sendGlobalRequest(b"reply", b"", wantReply=1)
        lateReply = self.assertFailure(lateReply, error.ConchError)
        lateReply.addCallback(
            lambda exc: self.assertEqual(_message(exc), "Connection stopped.")
        )
        # No new traffic was emitted for the refused inner work.
        self.assertEqual(self.transport.packets, [])
        return lateReply


# ---------------------------------------------------------------------------
# Carrier 3: SSHUserAuthServer login timeout cancellation / firing
# ---------------------------------------------------------------------------


class UserAuthLoginTimeoutLedgerTests(unittest.TestCase):
    if not cryptography:
        skip = "Cannot run without cryptography"

    def setUp(self):
        self.portal = Portal(Realm())
        self.portal.registerChecker(PasswordChecker())
        self.transport = FakeTransport(self.portal)
        self.ledger = self.transport.enableServiceLedger()
        self.clock = task.Clock()
        self.auth = userauth.SSHUserAuthServer()
        self.auth.clock = self.clock
        self.auth.transport = self.transport
        self.auth.serviceStarted()
        self.handle = self.auth._cancelLoginTimeout
        self.assertIsNotNone(self.handle)

    def test_serviceStopCancelsTimeoutAndItNeverFires(self):
        """
        Stopping the service settles the timeout by cancellation: the
        DelayedCall is inactive/cancelled, advancing the same clock past the
        deadline sends no disconnect, and a nested direct timeout cannot
        rewrite the cancelled fate.
        """
        self.auth.serviceStopped()

        self.assertFalse(self.handle.active())
        self.assertTrue(self.handle.cancelled)
        self.assertEqual(self.ledger.cancelledLoginTimeouts, [self.handle])
        self.assertEqual(self.ledger.firedLoginTimeouts, [])

        self.clock.advance(self.auth.loginTimeout + 1)
        self.assertFalse(self.transport.lostConnection)
        self.assertEqual(self.transport.packets, [])

        # Inner timeout call after the committed cancellation.
        self.auth.timeoutAuthentication()
        self.assertFalse(self.transport.lostConnection)
        self.assertEqual(self.transport.packets, [])
        self.assertEqual(self.ledger.firedLoginTimeouts, [])
        self.assertEqual(self.ledger.cancelledLoginTimeouts, [self.handle])

        # A repeated stop is harmless.
        self.auth.serviceStopped()
        self.assertEqual(self.transport.packets, [])

    def test_timeoutFiringDisconnectsAndCannotBeCancelledAfter(self):
        """
        Letting the handle fire on the same clock settles the timeout by
        disconnection: exactly one MSG_DISCONNECT is emitted, the fired
        handle is inactive without being cancelled, and a later stop or
        nested direct timeout cannot cancel/re-fire it.
        """
        self.clock.advance(self.auth.loginTimeout)

        self.assertFalse(self.handle.active())
        self.assertFalse(self.handle.cancelled)
        self.assertEqual(self.ledger.firedLoginTimeouts, [self.handle])
        self.assertEqual(self.ledger.cancelledLoginTimeouts, [])
        self.assertTrue(self.transport.lostConnection)
        self.assertEqual(len(self.transport.packets), 1)
        self.assertEqual(self.transport.packets[0][0], transport.MSG_DISCONNECT)

        self.auth.serviceStopped()
        self.auth.timeoutAuthentication()
        self.assertEqual(len(self.transport.packets), 1)
        self.assertEqual(self.ledger.firedLoginTimeouts, [self.handle])
        self.assertEqual(self.ledger.cancelledLoginTimeouts, [])

    def test_rescheduledHandleSettlesIndependentlyOnSameClock(self):
        """
        A handle scheduled after the first one was cancelled is a distinct
        settlement on the same clock/transport: the old stays cancelled while
        the new one may fire and disconnect.
        """
        self.auth.serviceStopped()
        self.auth.serviceStarted()
        newHandle = self.auth._cancelLoginTimeout
        self.assertIsNotNone(newHandle)
        self.assertIsNot(newHandle, self.handle)

        self.clock.advance(self.auth.loginTimeout)

        self.assertFalse(self.handle.active())
        self.assertFalse(newHandle.active())
        self.assertTrue(self.transport.lostConnection)
        self.assertEqual(self.ledger.cancelledLoginTimeouts, [self.handle])
        self.assertEqual(self.ledger.firedLoginTimeouts, [newHandle])


# ---------------------------------------------------------------------------
# Ledger disabled: every exit keeps its historical behavior
# ---------------------------------------------------------------------------


class LedgerDisabledPinTests(unittest.TestCase):
    if not cryptography:
        skip = "Cannot run without cryptography"

    def test_transportHasNoLedgerByDefault(self):
        proto = MockTransportBase()
        self.assertIsNone(proto.serviceLedger)
        self.assertEqual(proto.enableServiceLedger(), proto.serviceLedger)
        self.assertIsInstance(proto.serviceLedger, _service_ledger.ServiceLedger)

    def test_disconnectWithoutLedgerLeavesQueueUntouched(self):
        """
        Without an enabled ledger, a mid-exchange disconnect keeps the
        historical behavior: the blocked queue is neither voided nor
        detached, so the rest of conch observes exactly what it did before.
        """
        wire = proto_helpers.StringTransport()
        proto = MockTransportBase()
        proto.makeConnection(wire)
        proto.dataReceived(b"SSH-2.0-BogoClient-1.2i\r\n")
        proto.dispatchMessage(
            transport.MSG_KEXINIT,
            test_transport.BaseSSHTransportTests._A_KEXINIT_MESSAGE,
        )
        proto.sendPacket(connection.MSG_CHANNEL_OPEN, common.NS(b"held"))
        queued = proto._blockedByKeyExchange

        proto.loseConnection()

        self.assertIs(proto._blockedByKeyExchange, queued)
        self.assertEqual(
            proto._blockedByKeyExchange,
            [(connection.MSG_CHANNEL_OPEN, common.NS(b"held"))],
        )
        self.assertNotIn(b"held", wire.value())

    def test_connectionWithoutLedgerKeepsPinnedExits(self):
        """
        A connection on a ledger-less transport keeps its pinned terminal
        behavior (this is the same code path exercised without a ledger by
        the existing connection suite; assert the marker is simply absent).
        """
        fakeTransport = FakeTransport(None)
        self.assertIsNone(fakeTransport.serviceLedger)
        conn = TestConnection()
        conn.transport = fakeTransport
        conn.serviceStarted()
        opening = TestChannel()
        conn.openChannel(opening)
        conn.serviceStopped()
        self.assertIsInstance(opening.openFailureReason, ConnectionLost)

    def test_userauthWithoutLedgerKeepsPinnedTimeoutCancel(self):
        """
        userauth on a ledger-less transport still cancels its timeout handle
        on stop and firing the clock afterwards disconnects nothing.
        """
        portal = Portal(Realm())
        portal.registerChecker(PasswordChecker())
        fakeTransport = FakeTransport(portal)
        self.assertIsNone(fakeTransport.serviceLedger)
        clock = task.Clock()
        auth = userauth.SSHUserAuthServer()
        auth.clock = clock
        auth.transport = fakeTransport
        auth.serviceStarted()
        handle = auth._cancelLoginTimeout
        auth.serviceStopped()
        self.assertFalse(handle.active())
        clock.advance(auth.loginTimeout + 1)
        self.assertEqual(fakeTransport.packets, [])
