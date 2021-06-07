import { __awaiter } from "tslib";
import { Browser as Browser } from '../auth-browser';
import { Capacitor } from '@capacitor/core';
import { Browser as CapBrowser } from '@capacitor/browser';
export class CapacitorBrowser extends Browser {
    closeWindow() {
        if (!CapBrowser)
            throw new Error("Capacitor Browser Is Undefined!");
        if (Capacitor.getPlatform() !== 'android') {
            CapBrowser.close();
        }
    }
    showWindow(url) {
        return __awaiter(this, void 0, void 0, function* () {
            const options = {
                url: url,
                windowName: '_self'
            };
            if (!CapBrowser)
                throw new Error("Capacitor Browser Is Undefined!");
            CapBrowser.addListener("browserFinished", () => {
                this.onCloseFunction();
            });
            CapBrowser.open(options);
            return;
        });
    }
}
