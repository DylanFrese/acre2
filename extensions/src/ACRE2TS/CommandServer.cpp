#include "CommandServer.h"

#include "TsFunctions.h"

#include "TextMessage.h"
#include "Log.h"

#include "TS3Client.h"

extern TS3Functions ts3Functions;

acre::Result CCommandServer::initialize(){
    TRACE("enter");

    return acre::Result::ok;
}

acre::Result CCommandServer::shutdown() {
    TRACE("enter");

    return acre::Result::ok;
}


acre::Result CCommandServer::sendMessage(IMessage *msg){
    LOCK(this);
    //LOG("Sending: %s", (const char *)msg->getData());
    ts3Functions.sendPluginCommand((unsigned __int64)ts3Functions.getCurrentServerConnectionHandlerID(),
        (const char *)this->getCommandId(),
        (const char *)msg->getData(),
        PluginCommandTarget_CURRENT_CHANNEL, NULL, NULL);
    //LOG("sending [%s], [%s]", this->getCommandId(), msg->getData());

    delete msg;

    UNLOCK(this);

    return acre::Result::ok;
}

acre::Result CCommandServer::handleMessage(unsigned char *data){
    CTextMessage *msg;
    //LOG("recv: [%s]", data);
    msg = new CTextMessage((char *)data, strlen((char *)data));
    if (CEngine::getInstance()->getRpcEngine() && (msg != nullptr)) {
        CEngine::getInstance()->getRpcEngine()->runProcedure((IServer *)this, (IMessage *)msg);
    }
    return acre::Result::ok;
}


acre::Result CCommandServer::release() {
    if (this->getCommandId()) {
        free(this->getCommandId());
    }

    return acre::Result::ok;
}


//
// constructor/destructor foo
//
CCommandServer::CCommandServer(const acre::id_t id) {
    this->setId(id);
}
CCommandServer::CCommandServer() {
    this->setCommandId(nullptr);
    this->setConnected(true);
}
