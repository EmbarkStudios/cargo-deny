import "../dist/src/index.js";

namespace Schemd;

/**
 * Add examples to the target type.
 *
 * @param value The examples array expressed via TypeSpec's literals syntax.
 */
extern dec examples(target: unknown, value: unknown[]);

/**
 * Generate `schemd` metadata for the schema on the target type.
 */
extern dec schemdSchema(target: unknown);

/**
 * Set a header that will be used instead of a generated one for this schema
 * in documentation.
 */
extern dec docHeader(
    target:
        | Reflection.Model
        | Reflection.Enum
        | Reflection.Union
        | Reflection.ModelProperty
        | Reflection.UnionVariant,
    header: valueof string
);

/**
 * Embed the documentation from the underlying referenced type by inlining
 * it in the current type's documentation.
 */
extern dec docInline(
    target: Reflection.ModelProperty | Reflection.UnionVariant
);
