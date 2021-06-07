import { Browser as Browser } from '../auth-browser';
import { Capacitor } from '@capacitor/core';
import { Browser as CapBrowser, OpenOptions } from '@capacitor/browser'

export class CapacitorBrowser extends Browser {
    public closeWindow(): void | Promise<void> {
        if(!CapBrowser)
            throw new Error("Capacitor Browser Is Undefined!");
            
        if(Capacitor.getPlatform() !== 'android'){
            CapBrowser.close();
        }       
    }

    public async showWindow(url: string): Promise<string | undefined> {
        const options : OpenOptions = {
            url : url,
            windowName: '_self'
        };

        if(!CapBrowser)
            throw new Error("Capacitor Browser Is Undefined!");

        CapBrowser.addListener("browserFinished",() => {
            this.onCloseFunction();
        });

        CapBrowser.open(options);
         
        return;
    } 
}
