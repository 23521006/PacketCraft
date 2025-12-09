export function clean(v) {
    if (v === null || v === undefined || v === "") return null;
    if (!isNaN(v)) return Number(v);
    return v;
}

export function removeNulls(obj) {
    for (const k in obj) {
        if (obj[k] === null || obj[k] === "") {
            delete obj[k];
        }
    }
    return obj;
}