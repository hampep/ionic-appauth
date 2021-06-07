export class Browser {
    constructor() {
        this.onCloseFunction = () => { };
    }
    browserCloseListener(closeBrowserEvent) {
        this.onCloseFunction = closeBrowserEvent;
    }
}
export class DefaultBrowser extends Browser {
    showWindow(url) {
        const openWindow = window.open(url, "_self");
        if (openWindow) {
            openWindow.addEventListener('beforeupload', () => this.onCloseFunction());
        }
        return;
    }
    closeWindow() {
        window.close();
    }
}
