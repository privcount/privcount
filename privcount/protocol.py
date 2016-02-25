import random, logging, json

from time import time

from twisted.internet import reactor
from twisted.protocols.basic import LineOnlyReceiver

PRIVCOUNT_HANDSHAKE_MAGIC = 759.623

class PrivCountProtocol(LineOnlyReceiver):
    '''
    The base protocol class for PrivCount. This class logs basic connection information when
    connections are made and lost, and tracks the validity of connections during the handshake
    process and execution of the protocol.
    '''

    def __init__(self, factory):
        self.factory = factory
        self.is_valid_connection = False
        self.client_cookie = None
        self.server_cookie = None

        '''here we use the LineOnlyReceiver's MAX_LENGTH to drop the connection
        if we receive too much data before the handshake validates it
        the handshake process itself transfers very little, so we can get
        away with a small buffer - after the handshake suceeds, we allow lines
        of longer length'''
        self.MAX_LENGTH = 256

    def connectionMade(self): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was made".format(peer.type, peer.host, peer.port))

    def lineReceived(self, line): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Received line '{}' from {}:{}:{}".format(line, peer.type, peer.host, peer.port))
        parts = [part.strip() for part in line.split(' ', 1)]
        if len(parts) > 0:
            event_type = parts[0]
            event_payload = parts[1] if len(parts) > 1 else ''
            self.process_event(event_type, event_payload)

    def sendLine(self, line): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Sending line '{}' to {}:{}:{}".format(line, peer.type, peer.host, peer.port))
        return LineOnlyReceiver.sendLine(self, line)

    def lineLengthExceeded(self, line): # overrides twisted function
        peer = self.transport.getPeer()
        logging.warning("Incomming line of length {} exceeded MAX_LENGTH of {}, dropping unvalidated connection to {}:{}:{}".format(len(line), self.MAX_LENGTH, peer.type, peer.host, peer.port))
        return LineOnlyReceiver.lineLengthExceeded(self, line)

    def process_event(self, event_type, event_payload):
        if event_type.startswith('HANDSHAKE'):
            self.handle_handshake_event(event_type, event_payload)
            return

        if self.is_valid_connection:
            is_valid = False

            if event_type.startswith('STATUS'):
                is_valid = self.handle_status_event(event_type, event_payload)
            elif event_type.startswith('START'):
                is_valid = self.handle_start_event(event_type, event_payload)
            elif event_type.startswith('STOP'):
                is_valid = self.handle_stop_event(event_type, event_payload)
            elif event_type.startswith('CHECKIN'):
                is_valid = self.handle_checkin_event(event_type, event_payload)

            self.is_valid_connection = is_valid

        if not self.is_valid_connection:
            self.protocol_failed()

    def handshake_succeeded(self):
        peer = self.transport.getPeer()
        logging.debug("Handshake with {}:{}:{} was successful".format(peer.type, peer.host, peer.port))
        self.is_valid_connection = True
        self.MAX_LENGTH = 512*1024 # now allow longer lines

    def handshake_failed(self):
        peer = self.transport.getPeer()
        logging.warning("Handshake with {}:{}:{} failed".format(peer.type, peer.host, peer.port))
        self.is_valid_connection = False
        self.transport.loseConnection()

    def protocol_succeeded(self):
        peer = self.transport.getPeer()
        logging.debug("Protocol with {}:{}:{} was successful".format(peer.type, peer.host, peer.port))
        self.transport.loseConnection()

    def protocol_failed(self):
        peer = self.transport.getPeer()
        logging.warning("Protocol with {}:{}:{} failed".format(peer.type, peer.host, peer.port))
        self.is_valid_connection = False
        self.transport.loseConnection()

    def connectionLost(self, reason): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was lost: {}".format(peer.type, peer.host, peer.port, reason.getErrorMessage()))

    def handle_handshake_event(self, event_type, event_payload):
        '''override this function in a subclass to handle the event type'''
        pass

    def handle_status_event(self, event_type, event_payload):
        '''override this function in a subclass to handle the event type'''
        pass

    def handle_start_event(self, event_type, event_payload):
        '''override this function in a subclass to handle the event type'''
        pass

    def handle_stop_event(self, event_type, event_payload):
        '''override this function in a subclass to handle the event type'''
        pass

    def handle_checkin_event(self, event_type, event_payload):
        '''override this function in a subclass to handle the event type'''
        pass

class PrivCountServerProtocol(PrivCountProtocol):

    def __init__(self, factory):
        PrivCountProtocol.__init__(self, factory)
        self.last_sent_time = 0.0
        self.client_uid = None

    def connectionMade(self): # overrides twisted function
        PrivCountProtocol.connectionMade(self)
        self.send_handshake_event()

    def send_handshake_event(self):
        # initiate the handshake with the client
        self.server_cookie = round(random.random(), 6)
        self.sendLine("HANDSHAKE1 {}".format(self.server_cookie))

    def handle_handshake_event(self, event_type, event_payload):
        is_valid = False
        parts = event_payload.strip().split()

        if event_type == "HANDSHAKE2" and len(parts) == 2:
            is_valid = True
            self.client_cookie = float(parts[0])
            client_password = float(parts[1])
            password = round(self.client_cookie * self.server_cookie * PRIVCOUNT_HANDSHAKE_MAGIC, 6)
            if client_password == float(str(password)):
                self.sendLine("HANDSHAKE3 SUCCESS")
                self.handshake_succeeded()
            else:
                self.sendLine("HANDSHAKE3 FAIL")
                self.handshake_failed()

        if not is_valid:
            self.handshake_failed()

    def handshake_succeeded(self):
        PrivCountProtocol.handshake_succeeded(self)
        self.send_status_event()

    def send_status_event(self):
        status = self.factory.get_status()
        self.sendLine("STATUS {} {}".format(time(), json.dumps(status)))
        self.last_sent_time = time()

    def handle_status_event(self, event_type, event_payload):
        parts = event_payload.split(' ', 1)

        if event_type == "STATUS" and len(parts) == 2:
            client_status = json.loads(parts[1])

            client_status['alive'] = time()
            client_status['host'] = self.transport.getPeer().host
            client_status['clock_skew'] = 0.0
            client_status['rtt'] = 0.0

            if self.last_sent_time > 0:
                client_status['rtt'] = client_status['alive'] - self.last_sent_time
                latency = client_status['rtt'] / 2.0
                client_time = float(parts[0])
                client_status['clock_skew'] = abs(time() - latency - client_time)
                self.last_sent_time = 0

            self.client_uid = "{}~{}".format(client_status['host'], client_status['name'])
            self.factory.set_client_status(self.client_uid, client_status)

            config = self.factory.get_stop_config(self.client_uid)
            if config is not None:
                self.send_stop_event(config)
            else:
                config = self.factory.get_start_config(self.client_uid)
                if config is not None:
                    self.send_start_event(config)
                else:
                    self.send_checkin_event()
            return True

        return False

    def send_start_event(self, config):
        assert config is not None
        self.sendLine("START {}".format(json.dumps(config)))

    def handle_start_event(self, event_type, event_payload):
        parts = event_payload.split(' ', 1)
        if event_type == "START" and len(parts) > 0:
            result_data = None
            if parts[0] == "SUCCESS" and len(parts) == 2:
                result_data = json.loads(parts[1])
            self.factory.set_start_result(self.client_uid, result_data)
            self.send_status_event()
            return True
        else:
            return False

    def send_stop_event(self, config):
        assert config is not None
        self.sendLine("STOP {}".format(json.dumps(config)))

    def handle_stop_event(self, event_type, event_payload):
        parts = event_payload.split(' ', 1)
        if event_type == "STOP" and len(parts) > 0:
            result_data = None
            if parts[0] == "SUCCESS" and len(parts) == 2:
                result_data = json.loads(parts[1])
            self.factory.set_stop_result(self.client_uid, result_data)
            self.send_status_event()
            return True
        else:
            return False

    def send_checkin_event(self):
        period = int(self.factory.get_checkin_period())
        self.sendLine("CHECKIN {}".format(period))

    def handle_checkin_event(self, event_type, event_payload):
        self.protocol_succeeded()
        return True

class PrivCountClientProtocol(PrivCountProtocol):

    def handshake_succeeded(self):
        PrivCountProtocol.handshake_succeeded(self)
        # for a reconnecting client, reset the exp backoff delay
        self.factory.resetDelay()

    def protocol_succeeded(self):
        PrivCountProtocol.protocol_succeeded(self)
        # for a reconnecting client, don't reconnect after this disconnection
        self.factory.stopTrying()

    def handle_handshake_event(self, event_type, event_payload):
        is_valid = False
        parts = event_payload.split()

        if event_type == "HANDSHAKE1" and len(parts) == 1:
            is_valid = True
            self.server_cookie = float(parts[0])
            self.client_cookie = round(random.random(), 6)
            password = round(self.client_cookie * self.server_cookie * PRIVCOUNT_HANDSHAKE_MAGIC, 6)
            self.sendLine("HANDSHAKE2 {} {}".format(self.client_cookie, password))
        elif event_type == "HANDSHAKE3" and len(parts) == 1:
            is_valid = True
            if parts[0] == "SUCCESS":
                self.handshake_succeeded()
            else:
                self.handshake_failed()

        if not is_valid:
            self.handshake_failed()

    def handle_status_event(self, event_type, event_payload):
        parts = event_payload.split(' ', 1)

        if event_type == "STATUS" and len(parts) == 2:
            server_time = float(parts[0])
            server_status = json.loads(parts[1])
            self.factory.set_server_status(server_status)

            status = self.factory.get_status()
            self.sendLine("STATUS {} {}".format(time(), json.dumps(status)))
            return True
        return False

    def handle_start_event(self, event_type, event_payload):
        start_config = json.loads(event_payload)
        result_data = self.factory.do_start(start_config)
        if result_data is not None:
            self.sendLine("START SUCCESS {}".format(json.dumps(result_data)))
        else:
            self.sendLine("START FAIL")
        return True

    def handle_stop_event(self, event_type, event_payload):
        stop_config = json.loads(event_payload)
        result_data = self.factory.do_stop(stop_config)
        if result_data is not None:
            self.sendLine("STOP SUCCESS {}".format(json.dumps(result_data)))
        else:
            self.sendLine("STOP FAIL")
        return True

    def handle_checkin_event(self, event_type, event_payload):
        if event_type == "CHECKIN":
            parts = event_payload.split()
            if len(parts) == 1:
                period = int(parts[0])
                reactor.callLater(period, self.factory.do_checkin) # pylint: disable=E1101
                self.sendLine("CHECKIN SUCCESS")
                self.protocol_succeeded()
                return True
        return False

class TorControlClientProtocol(LineOnlyReceiver):

    def __init__(self, factory):
        self.factory = factory
        self.state = None

    def connectionMade(self): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was made".format(peer.type, peer.host, peer.port))

        self.sendLine("AUTHENTICATE")
        self.state = 'authenticating'

    def lineReceived(self, line): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Received line '{}' from {}:{}:{}".format(line, peer.type, peer.host, peer.port))

        if self.state == 'authenticating' and line.strip() == "250 OK":
            self.sendLine("SETEVENTS PRIVCOUNT")
            self.state = 'processing'
        elif self.state == 'processing' and line.startswith("650 PRIVCOUNT "):
            _, _, event = line.partition(" PRIVCOUNT ") # returns: part1, separator, part2
            if event != '':
                if not self.factory.handle_event(event):
                    self.quit()

    def quit(self):
        self.sendLine("QUIT")

    def connectionLost(self, reason): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was lost: {}".format(peer.type, peer.host, peer.port, reason.getErrorMessage()))

class TorControlServerProtocol(LineOnlyReceiver):
    """
    The server side of the Tor control protocol as exercised by PrivCount.

    This is useful for emulating a Tor control server for testing purposes.

    Example protocol run:
    telnet localhost 9051
    Connected to localhost.
    Escape character is '^]'.
    AUTHENTICATE
    250 OK
    SETEVENTS PRIVCOUNT
    552 Unrecognized event "PRIVCOUNT"
    SETEVENTS BW
    250 OK
    650 BW 422670 576069
    QUIT
    250 closing connection
    Connection closed by foreign host.
    """

    def __init__(self, factory):
        self.factory = factory
        self.authenticated = False

    def connectionMade(self): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was made".format(peer.type, peer.host, peer.port))

    def lineReceived(self, line): # overrides twisted function
        peer = self.transport.getPeer()
        line = line.strip()
        parts = line.split(' ')

        logging.debug("Received line '{}' from {}:{}:{}".format(line, peer.type, peer.host, peer.port))

        if not self.authenticated:
            if line == "AUTHENTICATE":
                self.sendLine("250 OK")
                self.authenticated = True
            else:
                self.sendLine("514 Authentication required.")
                self.transport.loseConnection()
        elif len(parts) > 0:
            if parts[0] == "SETEVENTS":
                if len(parts) == 2:
                    if parts[1] == "PRIVCOUNT":
                        self.sendLine("250 OK")
                        self.factory.start_injecting()
                    else:
                        self.sendLine('552 Unrecognized event "{}"'.format(parts[1]))
                        self.factory.stop_injecting()
                else:
                    self.sendLine('552 Unrecognized event ""')
            elif parts[0] == "QUIT":
                self.factory.stop_injecting()
                self.sendLine("250 closing connection")
                self.transport.loseConnection()
            else:
                self.sendLine('510 Unrecognized command "{}"'.format(parts[0]))
        else:
            self.sendLine('510 Unrecognized command ""')

    def connectionLost(self, reason): # overrides twisted function
        peer = self.transport.getPeer()
        logging.debug("Connection with {}:{}:{} was lost: {}".format(peer.type, peer.host, peer.port, reason.getErrorMessage()))
