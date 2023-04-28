#include "script_component.hpp"
/*
 * Author: ACRE2Team
 * Sends a message to the VOIP plugin via the ACRE2Arma extension.
 *
 * Arguments:
 * 0: Message <STRING>
 *
 * Return Value:
 * Successful Sending <BOOL>
 *
 * Example:
 * ["getPluginVersion:,"] call acre_sys_io_fnc_sendMessage
 *
 * Public: No
 */

_startTime = diag_tickTime;
if (GVAR(pipeCode) == "1") exitWith {
    private _ret = "ACRE2Arma" callExtension ("2" + _this);
    true
};

diag_log (format ["Sending message took %1", diag_tickTime - _startTime]);

false
