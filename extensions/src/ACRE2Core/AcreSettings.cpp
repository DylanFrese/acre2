#include "AcreSettings.h"
#include "Log.h"
#include <fstream>

acre::Result CAcreSettings::save(std::string filename) {
    // Write the shit out by hand for now
    std::ofstream iniFile;

    iniFile.open(filename, std::ios::trunc);
    if (!iniFile.is_open()) {
        return acre::Result::error;
    }
    iniFile << "[acre2]\n";
    iniFile << "lastVersion = " << ACRE_VERSION << ";\n";
    iniFile << "globalVolume = " << this->m_GlobalVolume << ";\n";
    iniFile << "premixGlobalVolume = " << this->m_PremixGlobalVolume << ";\n";
    iniFile << "disableUnmuteClients = " << (this->m_DisableUnmuteClients ? "true" : "false") << ";\n";
    iniFile << "disableChannelSwitch = " << (this->m_DisableChannelSwitch ? "true" : "false") << ";\n";
#ifdef __linux__
    iniFile << "wineSocketPort = " << (this->m_WineSocketPort) << ";\n";
#endif

    //LOG("Config Save: %f,%f", m_GlobalVolume, m_PremixGlobalVolume);
    iniFile.flush();
    iniFile.close();

    return acre::Result::ok;
}

acre::Result CAcreSettings::load(std::string filename) {
    // Write the shit out by hand for now
    ini_reader config(filename);

    if (config.ParseError() < 0) {
        LOG("Failed to load ACRE ini file. Using defaults...");
        this->save(filename);
        return acre::Result::error;
    } else {
        LOG("Successfully loaded ACRE ini file (any failures above can be ignored).");
    }

    this->m_LastVersion = config.Get("acre2", "lastVersion", ACRE_VERSION);
    this->m_GlobalVolume = (float)config.GetReal("acre2", "globalVolume", 1.0f);
    this->m_PremixGlobalVolume = (float)config.GetReal("acre2", "premixGlobalVolume", 1.0f);
    this->m_DisableUnmuteClients = config.GetBoolean("acre2", "disableUnmuteClients", false);
    this->m_DisableChannelSwitch = config.GetBoolean("acre2", "disableChannelSwitch", false);
#ifdef __linux__
    this->m_WineSocketPort = config.GetInteger("acre2", "wineSocketPort", 19141);
#endif

    //LOG("Config Load: %f,%f", m_GlobalVolume, m_PremixGlobalVolume);
    this->m_Path = filename;

    return acre::Result::ok;
}

acre::Result CAcreSettings::save() {
    // Write the shit out by hand for now
    return this->save(this->m_Path);
}
acre::Result CAcreSettings::load() {
    // Write the shit out by hand for now
    return load(this->m_Path);
}

CAcreSettings::CAcreSettings() :
#ifdef __linux__
    m_WineSocketPort(19141),
#endif
    m_GlobalVolume(1.0f),
    m_PremixGlobalVolume(1.0f),
    m_DisablePosition(false),
    m_DisableMuting(false),
    m_EnableAudioTest(false),
    m_DisableRadioFilter(false),
    m_DisableUnmuteClients(false),
    m_DisableChannelSwitch(false),
    m_LastVersion(ACRE_VERSION),
    m_Path("acre2.ini")
    {
    // Set defaults!
    //LOG("Config Singleton Initialized");
}


CAcreSettings::~CAcreSettings() {

}
