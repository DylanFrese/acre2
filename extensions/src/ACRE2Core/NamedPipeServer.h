#include "compat.h"
#include "Macros.h"
#include "Lockable.h"
#include "Types.h"
#include "IMessage.h"
#include "IServer.h"
#include "AcreSettings.h"

#ifdef WIN32
#include <concurrent_queue.h>
#include <winsock2.h>
#else
#include <tbb/concurrent_queue.h>
namespace concurrency = tbb;
#endif

#include <thread>
#include <algorithm>
#include <set>
#include <string>

class CNamedPipeServer : public IServer, public CLockable {
public:
    CNamedPipeServer(std::string fromPipeName, std::string toPipeName);
    ~CNamedPipeServer(void);

    acre::Result readLoop();
    acre::Result sendLoop();

    acre::Result initialize( void );
    acre::Result shutdown( void );

    acre::Result handleMessage(unsigned char* data) { (void)data; return acre::Result::notImplemented; }
    acre::Result handleMessage(unsigned char* data, size_t length) { (void)data; return acre::Result::notImplemented; }


    acre::Result sendMessage( IMessage *message );

    acre::Result release( void ) { return acre::Result::ok; };

    acre::Result checkServer( void ); // DRM

    char *currentServerId;

    inline void setConnectedWrite(const bool value) { m_connectedWrite = value; }
    inline bool getConnectedWrite() const { return m_connectedWrite; }

    inline void setConnectedRead(const bool value) { m_connectedRead = value; }
    inline bool getConnectedRead() const { return m_connectedRead; }

    inline void setShuttingDown(const bool value) { m_shuttingDown = value; }
    inline bool getShuttingDown() const { return m_shuttingDown; }

    inline void setId(const acre::id_t value) final { m_id = value; }
    inline acre::id_t getId() const final { return m_id; }

    bool getConnected() const final { return (getConnectedRead() && getConnectedWrite()); };
    void setConnected(bool value) final { setConnectedRead(value); setConnectedWrite(value); };

protected:
    acre::id_t m_id;
    bool       m_connectedWrite;
    bool       m_connectedRead;
    bool       m_shuttingDown;

private:
    concurrency::concurrent_queue<IMessage *> m_sendQueue;
    std::thread m_readThread;
    std::thread m_sendThread;
    std::set<std::string> validTSServers;
#ifdef WIN32
    SOCKET m_sockFD;
#else
    int m_sockFD;
#endif
    int m_clientFD;

    uint16_t acreListenPort = CAcreSettings::getInstance()->getSocketPort();

};
