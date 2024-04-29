import type { LoadContext, Plugin } from "@docusaurus/types";
import { z } from "zod";

const PluginOptions = z
    .object({
        dashieSchemaPath: z.string(),
    })
    .strict();

type PluginOptions = z.infer<typeof PluginOptions>;

export function validateOptions({ options }: { options: unknown }) {
    return PluginOptions.parse(options)
}

export default function dashiePlugin(context: LoadContext, options: PluginOptions): Plugin {
    return {
        name: "docus-plugin-dashie",
        async contentLoaded({ content, actions }) {
            const { addRoute } = actions;
            addRoute({
                path: "/dashie",
                component: "@theme/Dashie",
                exact: true,
            });
        },
    };
}
