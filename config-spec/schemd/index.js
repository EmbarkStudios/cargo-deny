import { setTypeSpecNamespace } from "@typespec/compiler";
import * as decorators from "./decorators.js";
export { $lib } from "./lib.js";

function decorator(fn) {
    const namespace = "Schemd";
    setTypeSpecNamespace(namespace, fn);
    return fn;
}

export const $schemdSchema = decorator(decorators.$schemdSchema);
export const $examples = decorator(decorators.$examples);
export const $logType = decorator(decorators.$logType);
export const $docHeader = decorator(decorators.$docHeader);
