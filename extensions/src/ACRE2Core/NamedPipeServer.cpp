#include "NamedPipeServer.h"
#include "TextMessage.h"
#include "Log.h"
#include "Engine.h"

#ifdef WIN32
#include <sddl.h>
#include <ws2tcpip.h>
#else
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#endif
#include <Tracy.hpp>

#ifdef WIN32
#define socketerror WSAGetLastError()
typedef int ssize_t;
typedef clock_t walltime_t;
#define SHUT_RDWR SD_BOTH
#else
#define closesocket close
#define socketerror errno
typedef timespec walltime_t;
#endif

CNamedPipeServer::CNamedPipeServer(std::string fromPipeName, std::string toPipeName) {
    this->setConnectedWrite(false);
    this->setConnectedRead(false);
    this->setShuttingDown(false);
}

CNamedPipeServer::~CNamedPipeServer( void ) {
    this->shutdown();
}

walltime_t getMonotime() {
#ifdef WIN32
    return clock();
#else
    walltime_t ret;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ret);
    return ret;
#endif
}

long diffMonotime(walltime_t current, walltime_t previous) {
#ifdef WIN32
    return ((current - previous) * 1000) / CLOCKS_PER_SEC;
#else
    time_t s = (current.tv_sec - previous.tv_sec);
    time_t ms = (time_t) ((current.tv_nsec - previous.tv_nsec) / 1000000);
    return s * 1000 + ms;
#endif
}

acre::Result CNamedPipeServer::initialize() {
    ZoneScoped;

#ifdef WIN32
    HANDLE writeHandle, readHandle;

    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) { LOG("InitializeSecurityDescriptor Error : %u", GetLastError()); }
    if (!SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE)) { LOG("SetSecurityDescriptorDacl Error : %u", GetLastError()); }
    if (!SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) { LOG("SetSecurityDescriptorControl Error : %u", GetLastError()); }
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), &sd, true };
#endif

    // open our pipe handle, then kick up a thread to monitor it and add shit to our queue
    // this end LISTENS and CREATES the pipe
    LOG("Opening game pipe...");

    this->m_sockFD = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(acreListenPort);
#ifdef WIN32
    listenAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
#else
    listenAddr.sin_addr = { inet_addr("127.0.0.1") };
#endif

    const char param = 1;
    setsockopt(this->m_sockFD, SOL_SOCKET, SO_REUSEADDR, &param, sizeof(int));
    int ret = bind(this->m_sockFD, (struct sockaddr *) &listenAddr, sizeof(listenAddr));

    if(ret) {
      LOG("Could not bind to port %d, error %d", acreListenPort, socketerror);
      return acre::Result::error;
    }

    LOG("Bound on port %d", acreListenPort);

    ret = listen(this->m_sockFD, 1);
    if (ret) {
      LOG("Could not listen on port %d, error %d", acreListenPort, socketerror);
      return acre::Result::error;
    }

    this->m_readThread = std::thread(&CNamedPipeServer::readLoop, this);
    this->m_sendThread = std::thread(&CNamedPipeServer::sendLoop, this);

    return acre::Result::ok;
}

acre::Result CNamedPipeServer::shutdown(void) {
    ZoneScoped;

    this->setShuttingDown(true);

    this->setConnectedWrite(false);
    this->setConnectedRead(false);

    ::shutdown(this->m_sockFD, SHUT_RDWR);
    closesocket(this->m_sockFD);

    // Read should initiate the full shutdown, so we wait for him to die first and we only wake him.
    if (this->m_readThread.joinable()) {
        this->m_readThread.join();
    }

    if (this->m_sendThread.joinable()) {
        this->m_sendThread.join();
    }

    this->setShuttingDown(false);

    return acre::Result::ok;
}

const char *sendFrameName = "NamedPipeServer - sending";

acre::Result CNamedPipeServer::sendLoop() {
    tracy::SetThreadName("NamedPipeServer::sendLoop");
    ssize_t bufferHead, len;
    while (!this->getShuttingDown()) {
        CEngine::getInstance()->getSoundEngine()->onClientGameConnected();
        while(!this->getConnectedWrite() && !this->getShuttingDown()) {
            Sleep(1);
        }

        walltime_t lastTick = getMonotime();
        while (this->getConnectedWrite()) {
            FrameMarkStart(sendFrameName);
            if (this->getShuttingDown()) {
                break;
            }

            walltime_t tick = getMonotime();
            if (diffMonotime(tick, lastTick) > PIPE_TIMEOUT) {
                LOG("No send message for %d seconds, disconnecting", (PIPE_TIMEOUT / 1000));
                this->setConnectedWrite(false);
                break;
            }

            IMessage *msg = nullptr;
            ZoneScoped;
            if (this->m_sendQueue.try_pop(msg)) {
                if (msg != nullptr) {
                    lastTick = getMonotime();
                    const uint32_t msgSize = (uint32_t)strlen((char *)msg->getData());
                    const uint32_t size = msgSize + 4;
                    char* writeBuffer = new char[size];
                    strncpy(writeBuffer + 4, (char *)msg->getData(), strlen((char *) msg->getData()));
                    writeBuffer[0] = (char) (msgSize >> 24);
                    writeBuffer[1] = (char) (msgSize >> 16);
                    writeBuffer[2] = (char) (msgSize >> 8);
                    writeBuffer[3] = (char) (msgSize);
                    if (size > 3) {
                        //LOCK(this);
                        this->lock();
                        bufferHead = 0;
                        while (bufferHead < size) {
                            len = send(this->m_clientFD, writeBuffer + bufferHead, size - bufferHead, 0);
                            bufferHead += len;
                            if (len == -1) {
                                LOG("Error when writing to socket: %d", socketerror);
                                this->setConnectedWrite(false);
                            };
                        };
                        this->unlock();
                    }
                    delete msg;
                }
            }
            FrameMarkEnd(sendFrameName);
            Sleep(1);
        }
        LOG("Write loop disconnected");
        Sleep(1);
    }
    TRACE("Sending thread terminating");

    return acre::Result::ok;
}

const char *receiveFrameName = "NamedPipeServer - receiving";

acre::Result CNamedPipeServer::readLoop() {
    tracy::SetThreadName("NamedPipeServer::readLoop");
    char *mBuffer = (char *)calloc(1, BUFSIZE);
    if (mBuffer == nullptr) {
        LOG("calloc failed: %d", errno);
    }

    LOG("starting read loop");

    ssize_t bufferHead;
    ssize_t len;
    char lengthBuffer[4];
    fd_set readfds;

    while (!this->getShuttingDown()) {
        FD_ZERO(&readfds);
        FD_SET(this->m_sockFD, &readfds);
        struct timeval tv = {
            0,
            50000 // 50 ms
        };

        if (select(this->m_sockFD + 1, &readfds, NULL, NULL, &tv) == 0) {
            continue;
        }

        this->m_clientFD = accept(this->m_sockFD, NULL, NULL);
        if (this->m_clientFD != -1) {
            LOG("Client connected");
            CEngine::getInstance()->getClient()->updateShouldSwitchChannel(false);
            CEngine::getInstance()->getClient()->unMuteAll();
            CEngine::getInstance()->getSoundEngine()->onClientGameConnected();
            this->setConnectedRead(true);
            this->setConnectedWrite(true);
        } else {
            this->setConnectedRead(false);
            this->setConnectedWrite(false);
            Sleep(1);

            continue;
        }
        walltime_t lastTick = getMonotime();
        while (this->getConnectedRead()) {
            if (this->getShuttingDown()) {
                break;
            }

            walltime_t tick = getMonotime();
            if (diffMonotime(tick, lastTick) > PIPE_TIMEOUT) {
                LOG("No read message for %d seconds, disconnecting", (PIPE_TIMEOUT / 1000));
                this->setConnectedWrite(false);
                this->setConnectedRead(false);
                break;
            }

            //Run channel switch to server channel
            if (CEngine::getInstance()->getClient()->shouldSwitchChannel()) {
                CEngine::getInstance()->getClient()->moveToServerChannel();
            }

            // Read exactly four bytes for the message length
            bufferHead = 0;
            while(bufferHead < 4) {
                len = recv(this->m_clientFD, (&lengthBuffer[0]) + bufferHead, 4 - bufferHead, 0);
                if (len == 0) {
                    this->setConnectedRead(false);
                    goto clientClose;
                } else if (len == -1) {
                    LOG("Error when reading from socket: %d", socketerror);
                    this->setConnectedRead(false);
                    goto clientClose;
                };
                bufferHead += len;
            };
            uint32_t messageLength = (((unsigned char) lengthBuffer[0]) << 24) +
                                     (((unsigned char) lengthBuffer[1]) << 16) +
                                     (((unsigned char) lengthBuffer[2]) << 8) +
                                     (unsigned char) lengthBuffer[3];
            FrameMarkStart(receiveFrameName);

            if (messageLength > BUFSIZE - 1) {
                LOG("Received too-large message with size %d", messageLength);
                this->setConnectedWrite(false);
                this->setConnectedRead(false);
                break;
            }

            mBuffer[messageLength] = 0x00;

            bufferHead = 0;
            while(bufferHead < messageLength) {
                len = recv(this->m_clientFD, (mBuffer) + bufferHead, messageLength - bufferHead, 0);
                if (len == 0) {
                    this->setConnectedRead(false);
                    goto clientClose;
                } else if (len == -1) {
                    LOG("Error when reading from socket: %d", socketerror);
                    this->setConnectedRead(false);
                    goto clientClose;
                };
                bufferHead += len;
            };

            // handle the packet and run it
            mBuffer[messageLength] = 0x00;
            //LOG("READ: %s", (char *)mBuffer);
            IMessage *const msg = new CTextMessage((char *)mBuffer, messageLength);
            TRACE("got and parsed message [%s]", msg->getData());
            if (msg != nullptr && msg->getProcedureName()) {

                // Do not free msg, this is deleted inside runProcedure()
                CEngine::getInstance()->getRpcEngine()->runProcedure(this, msg);

                lastTick = getMonotime();
                //TRACE("tick [%d], [%s]",lastTick, msg->getData());
            }
            // wait 1ms for new msg so we dont hog cpu cycles
            FrameMarkEnd(receiveFrameName);

            Sleep(1);
        }

clientClose:
        this->setConnectedWrite(false);
        this->setConnectedRead(false);
        closesocket(this->m_clientFD);

        //Run channel switch to original channel
        CEngine::getInstance()->getClient()->moveToPreviousChannel();
        CEngine::getInstance()->getSoundEngine()->onClientGameDisconnected();
        LOG("Client disconnected");
        CEngine::getInstance()->getClient()->unMuteAll();

        // Clear the send queue since client disconnected
        this->m_sendQueue.clear();

        // send an event that we have disconnected
        if (CEngine::getInstance()->getExternalServer()->getConnected()) {
            CEngine::getInstance()->getExternalServer()->sendMessage(
                CTextMessage::formatNewMessage("ext_reset",
                    "%d,",
                    CEngine::getInstance()->getSelf()->getId()
                )
            );
        }
        Sleep(1);
    }

    if (mBuffer) {
        free(mBuffer);
    }

    TRACE("Receiving thread terminating");

    return acre::Result::ok;
}

acre::Result CNamedPipeServer::sendMessage( IMessage *message ) {
    if (message) {
        TRACE("sending [%s]", message->getData());
        this->m_sendQueue.push(message);
        return acre::Result::ok;
    } else {
        return acre::Result::error;
    }
}

acre::Result CNamedPipeServer::checkServer( void ) {
    std::string uniqueId = CEngine::getInstance()->getClient()->getUniqueId();
    if (uniqueId != "" && this->validTSServers.find(uniqueId) == this->validTSServers.end()) {
#ifdef WIN32
        MessageBoxA(NULL, "This server is NOT registered for ACRE2 testing! Please remove the plugin! Teamspeak will now close.", "ACRE Error", MB_OK | MB_ICONEXCLAMATION);
        TerminateProcess(GetCurrentProcess(), 0);
#else
#endif
    }
    return acre::Result::ok;
}
