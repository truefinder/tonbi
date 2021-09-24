
rule electron_setting1 : electron 
{
    strings :
        $fg1 = "nodeIntegration"
        $fg2 = "nodeIntegrationInWorker"
        $fg3 = "nodeIntegrationInSubFrames" 
        $fg4 = "allowRunningInsecureContent"
        $fg5 = "enableRemoteModule"
        $fg6 = "nativeWindowOpen"
        $fg7 = "webviewTag"

        $tg1 = "contextIsolation"
        $tg2 = "safeDialogs"
        $tg3 = "sandbox"
        $tg4 = "webSecurity"

        $pre = /preload.*:/

        $true = /.*:.*true/
        $false = /.*:.*false/ 

    condition: 
        (1 of ($fg*) and $true) or 
        (1 of ($tg*) and $false) or 
        $pre

}

rule electron_setting2 : electron 
{
    strings : 
        $set1 = "devTools"
        $set2 = "BrowserWindow.webContents.openDevTools("
        $set3 = "enableWebSQL"
        $set4 = "openExternal("
        $set5 = "ELECTRON_RUN_AS_NODE"
    condition: 
        any of them 
        
}

