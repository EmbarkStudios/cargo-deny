import * as tsp from "@typespec/compiler";
import { setJsonSchemaExtension, states } from "./common.js";

export * from "./schemd-schema.js";

/**
 * @internal Log the type to the console.
 */
export function $logType(_context: tsp.DecoratorContext, target: unknown) {
  console.log(target);
}

export const $examples = makeExtension("examples");

function makeExtension(key: string) {
  return (context: tsp.DecoratorContext, target: tsp.Type, value: string) => {
    setJsonSchemaExtension(context, target, key, value);
  };
}

export function $docHeader(
  context: tsp.DecoratorContext,
  target: tsp.Type,
  header: string
) {
  console.log("Setting doc header");

  // Workaround for https://github.com/microsoft/typespec/issues/3391
  if (target.kind == "ModelProperty" || target.kind == "UnionVariant") {
    const xSchemd = states.xSchemd(context, target.type);
    if (xSchemd.docHeader == null) {
      xSchemd.docHeader = header;
      return;
    }
    context.program.reportDiagnostic({
      code: "schemd/doc-header-conflict",
      message:
        `Doc header on the ${target.kind} conflicts with the` +
        `doc header on the type of this ${target.kind} itself. ` +
        "The doc header on the type will be used, and this one " +
        "will be ignored.",
      target,
      severity: "warning",
    });
    return;
  }

  const xSchemd = states.xSchemd(context, target);
  xSchemd.docHeader = header;
}

// TODO:
export function $docInline(
  context: tsp.DecoratorContext,
  target: tsp.Type,
) {
  const xSchemd = states.xSchemd(context, target);

  xSchemd.docInline = true;
}
