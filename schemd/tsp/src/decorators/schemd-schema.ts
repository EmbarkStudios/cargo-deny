import * as tsp from "@typespec/compiler";
import * as tspJsonSchema from "@typespec/json-schema";
import { states } from "./common.js";
import { traverseTypes } from "../utils.js";

export function $schemdSchema(context: tsp.DecoratorContext, target: tsp.Type) {
  traverseTypes(target, (type) => {
    switch (type.kind) {
      case "Enum":
      case "Union":
      case "Scalar":
      case "Model": {
        const id = tspJsonSchema.getId(context.program, type);
        if (id == null && type.name != null) {
          tspJsonSchema.$id(context, type, `#/$defs/${type.name}`);
        }
      }
    }

    switch (type.kind) {
      case "Enum": {
        const xSchemd = states.xSchemd(context, type);
        xSchemd.members = [...type.members.values()].map((member) => ({
          description: tsp.getDoc(context.program, member),
          title: tsp.getSummary(context.program, member),
        }));
      }
    }
  });
}
