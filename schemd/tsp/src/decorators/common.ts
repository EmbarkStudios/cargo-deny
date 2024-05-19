import * as tsp from "@typespec/compiler";
import * as tspUtils from "@typespec/compiler/utils";
import { $lib } from "../lib.js";
import * as tspJsonSchema from "@typespec/json-schema";

const symbols = {
  xSchemd: $lib.createStateSymbol("x-schemd"),
};

export const states = {
  xSchemd: (context: tsp.DecoratorContext, target: tsp.Type): XSchemd => {
    const map = context.program.stateMap(symbols.xSchemd);
    if (map.has(target)) {
      return map.get(target);
    }

    // HACK: make the JSONSchema emitter think as if the value
    // specified here is a constant literal defined directly in
    // terms of a JS object shape.
    const obj = {
      kind: "EnumMember",
      value: {},
    };
    setJsonSchemaExtension(context, target, "x-schemd", obj);
    map.set(target, obj.value);
    return obj.value;
  },
};

type XSchemd = {
  members?: XSchemdMember[];
  docHeader?: string;
  docInline?: boolean;
};

type XSchemdMember = {
  title?: string;
  description?: string;
};

export function setJsonSchemaExtension(
  context: tsp.DecoratorContext,
  target: tsp.Type,
  key: string,
  value: unknown
) {
  const namespace = { name: "JsonSchema" };
  const properties = tspUtils.createRekeyableMap([["value", { type: value }]]);

  tspJsonSchema.$extension(context, target, key, {
    kind: "Model",
    name: "Json",
    // We ignore type errors here because we construct partial objects of these
    // types here. This is a workaround for the lack of proper library support
    // to set custom extensions for JSON Schema:
    // https://github.com/microsoft/typespec/issues/3336
    //
    // @ts-expect-error
    namespace,
    // @ts-expect-error
    properties,
  });
}
