import "./schemd";

namespace Schemd;

/**
 * Add examples to the target type.
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
