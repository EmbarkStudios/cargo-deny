import type { LoadContext, Plugin } from "@docusaurus/types";
import { z } from "zod";

const PluginOptions = z
    .object({
        schemdSchemaPath: z.string(),
    })
    .strict();

type PluginOptions = z.infer<typeof PluginOptions>;

export function validateOptions({ options }: { options: unknown }) {
    return PluginOptions.parse(options)
}

export default function schemdPlugin(context: LoadContext, options: PluginOptions): Plugin {
    return {
        name: "docus-plugin-schemd",
        async contentLoaded({ content, actions }) {
            const { addRoute } = actions;
            addRoute({
                path: "/schemd",
                component: "@theme/Schemd",
                exact: true,
            });
        },
    };
}
