import * as tsp from "@typespec/compiler";

export function traverseTypes(
  type: tsp.Type,
  visit: (type: tsp.Type) => void
): void {
  visit(type);
  const recurse = (type: tsp.Type) => traverseTypes(type, visit);

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
