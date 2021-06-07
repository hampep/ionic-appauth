import { __awaiter } from "tslib";
import { Storage } from '@capacitor/storage';
export class CapacitorStorage {
    getItem(name) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Storage)
                throw new Error("Capacitor Storage Is Undefined!");
            const returned = yield Storage.get({ key: name });
            return returned.value;
        });
    }
    removeItem(name) {
        if (!Storage)
            throw new Error("Capacitor Storage Is Undefined!");
        return Storage.remove({ key: name });
    }
    clear() {
        if (!Storage)
            throw new Error("Capacitor Storage Is Undefined!");
        return Storage.clear();
    }
    setItem(name, value) {
        if (!Storage)
            throw new Error("Capacitor Storage Is Undefined!");
        return Storage.set({ key: name, value: value });
    }
}
