//@ts-check
import { ListenerFlow, getDoc, navigateType } from "@typespec/compiler";
import { createRekeyableMap } from "@typespec/compiler/utils";
import * as jsonSchema from "@typespec/json-schema";
import { $lib } from "./lib.js";

export function $logType(context, target) {
    console.log(target);
}

export const $examples = makeExtension("examples");

/**
 * @param {string} key
 */
function makeExtension(key) {
    return (context, target, value) => {
        setExtension(context, target, key, value);
    };
}

/**
 * @param {import("@typespec/compiler").DecoratorContext} context
 * @param {import("@typespec/compiler").Type} target
 * @param {string} key
 * @param {unknown} value
 */
function setExtension(context, target, key, value) {
    jsonSchema.$extension(context, target, key, {
        kind: "Model",
        name: "Json",
        namespace: { name: "JsonSchema" },
        properties: createRekeyableMap([["value", { type: value }]])
    })
}

/**
 * @param {import("@typespec/compiler").DecoratorContext} context
 * @param {import("@typespec/compiler").Type} target
 * @param {string} header
 */
export function $docHeader(context, target, header) {
    console.log("Setting docs header");

    if (target.kind == "ModelProperty" || target.kind == "UnionVariant") {
        const xSchemd = states.xSchemd(context, target.type);
        if (xSchemd.docHeader == null) {
            xSchemd.docHeader = header;
            return;
        }
        context.program.reportDiagnostic({
            code: "schemd/docs-header-conflict",
            message:
                `Docs header on the ${target.kind} conflicts with the` +
                `docs header on the type of this ${target.kind} itself. ` +
                "The docs header on the type will be used, and this one " +
                "will be ignored.",
            target,
            severity: "warning",
        });
        return;
    }

    const xSchemd = states.xSchemd(context, target);
    xSchemd.docHeader = header;
}

export function $docInline(context, target, doc) {

}

/**
 * @param {import("@typespec/compiler").DecoratorContext} context
 * @param {import("@typespec/compiler").Type} target
 */
export function $schemdSchema(context, target) {
    traverseTypes(target, type => {
        switch (type.kind) {
            case "Enum":
            case "Union":
            case "Scalar":
            case "Model": {
                const id = jsonSchema.getId(context.program, type);
                if (id == null && type.name != null) {
                    jsonSchema.$id(context, type, `#/$defs/${type.name}`);
                }
            }
        }

        switch (type.kind) {
            case "Enum": {
                const xSchemd = states.xSchemd(context, type);
                xSchemd.members = [...type.members.values()].map(member => ({
                    description: getDoc(context.program, member) ?? null
                }));
            }
        }
    })
}

const symbols = {
    xSchemd: $lib.createStateSymbol("x-schemd"),
};

const states = {
    /**
     * @param {import("@typespec/compiler").DecoratorContext} context
     * @param {import("@typespec/compiler").Type} target
     * @returns {{
     *    members?: {
     *      description?: string | null
     *    }[],
     *    docHeader?: string
     * }}
     */
    xSchemd: (context, target) => {
        const map = context.program.stateMap(symbols.xSchemd);
        if (map.has(target)) {
            return map.get(target);
        }

        // HACK: make the JSONSchema emitter think as if the value
        // specified here is a constant literal defined directly in
        // terms of a JS object shape.
        const obj = {
            kind: "EnumMember",
            value: {}
        };
        setExtension(context, target, "x-schemd", obj);
        map.set(target, obj.value);
        return obj.value;
    }
}


/**
 * @param {import("@typespec/compiler").Type} type
 * @param {(type: import("@typespec/compiler").Type) => ListenerFlow | undefined | void} visit
 */
function traverseTypes(type, visit) {
    visit(type);
    const recurse = (type) => traverseTypes(type, visit);

    switch (type.kind) {
        case "Model": {
            for (const property of type.properties.values()) {
                recurse(property);
            }
            if (type.indexer != null) {
                recurse(type.indexer.key);
                recurse(type.indexer.value);
            }
            if (type.baseModel) {
                recurse(type.baseModel);
            }
            break;
        }
        case "ModelProperty": {
            recurse(type.type);
            break;
        }
        case "Tuple": {
            for (const element of type.values) {
                recurse(element);
            }
            break;
        }
        case "Union": {
            for (const variant of type.variants.values()) {
                recurse(variant);
            }
            break;
        }
        case "UnionVariant": {
            recurse(type.type);
            break;
        }
        case "Enum": {
            for (const member of type.members.values()) {
                recurse(member);
            }
            break;
        }
    }
}
