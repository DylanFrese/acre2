#pragma once

#include "IClient.h"
#include "MumbleFunctions.h"

#include <string>
#include <thread>
#include <vector>

class CMumbleClient : public IClient {
public:
    CMumbleClient()        = default;
    ~CMumbleClient() final = default;

    acre::Result initialize(void) final;

    acre::Result setMuted(const acre::id_t id_, const bool muted_) final;
    acre::Result setMuted(std::list<acre::id_t> idList_, const bool muted_) final;

    acre::Result getMuted(const acre::id_t id_) final;

    acre::Result stop() final;
    acre::Result start(const acre::id_t id_) final;

    acre::Result enableMicrophone(const bool status_) final;

    bool getVAD();

    /*!
     * \brief Handles local player starting speaking.
     *
     * \param[in]    speakingType_    ACRE speaking type
     *
     * \return       acre::Result::ok if operation successful
     */
    acre::Result localStartSpeaking(const acre::Speaking speakingType_) final;

    /*!
     * \brief Handles local player starting speaking.
     *
     * \param[in]    speakingType_    ACRE speaking type
     * \param[in]    radioId_         Unique radio ideintifier
     *
     * \return       acre::Result::ok if operation successful
     */
    acre::Result localStartSpeaking(const acre::Speaking speakingType_, std::string radioId_) final;

    /*!
     * \brief Handles local player stopping speaking.
     *
     * \param[in]    speakingType_    ACRE speaking type
     *
     * \return       acre::Result::ok if operation successful
     */
    acre::Result localStopSpeaking(const acre::Speaking speakingType_) final;

    /*!
     * \brief Gets client id of a headless client
     *
     * \param[in]    targetClientName_ Target's DisplayName in TS
     *
     * \return       acre::id_t
     */
    acre::id_t getClientIDByName(const std::string &targetClientName_);

    std::string getTempFilePath(void) final;
    std::string getConfigFilePath(void) final;

    acre::Result playSound(std::string path_, acre::vec3_fp32_t position_, const float32_t volume_, const int32_t looping_) final;

    std::string getUniqueId() final;
    std::string getServerName(void) final;
    std::string getChannelName(void) final;
    std::string getChannelUniqueID(void) final;

    acre::Result microphoneOpen(const bool status_) final;

    acre::Result unMuteAll(void) final;

    acre::Result moveToServerChannel() final;
    acre::Result moveToPreviousChannel() final;
    uint64_t findChannelByNames(std::vector<std::string> details_) final;

    acre::Result updateChannelDetails(std::vector<std::string> details_) final;
    acre::Result updateShouldSwitchChannel(const bool state_) final;
    bool shouldSwitchChannel() final;

private:
    bool currentStatus;
    std::thread m_versionThreadHandle;
    char *m_vadLevel = nullptr;

    mumble_channelid_t getCurrentChannelId();
    std::string getChannelName(mumble_channelid_t channel);
};
