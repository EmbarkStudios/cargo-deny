use crate::md_doc::mir;
use crate::prelude::*;
use crate::{md_ast, md_doc, source};
use camino::Utf8PathBuf;
use heck::ToKebabCase;
use mdbook::book::{self, Book};
use mdbook::preprocess::PreprocessorContext;
use mdbook::BookItem;
use serde::Deserialize;
use std::path::PathBuf;

const ROOT_PLACEHOLDER: &str = "{{ schemd-root }}";
const TYPE_INDEX_PLACEHOLDER: &str = "{{ schemd-type-index }}";

pub(super) fn run(ctx: PreprocessorContext, book: Book) -> Result<Book> {
    Context::new(ctx)?.run(book)
}

struct Context {
    config: Config,
    ctx: PreprocessorContext,
}

impl Context {
    const NAME: &'static str = "schemd";

    fn new(ctx: PreprocessorContext) -> Result<Self> {
        let config = Config::from_ctx(&ctx)?;

        let book_version = semver::Version::parse(&ctx.mdbook_version)?;
        let version_req = semver::VersionReq::parse(mdbook::MDBOOK_VERSION)?;

        if version_req.matches(&book_version) {
            warn!(
                "The {} preprocessor was built against version {} of mdbook, \
                but we're being called from version {}. There could be breaking \
                changes in mdbook API, which may lead to errors down the line",
                Self::NAME,
                mdbook::MDBOOK_VERSION,
                ctx.mdbook_version
            );
        }

        Ok(Self { config, ctx })
    }

    fn run(&self, mut book: Book) -> Result<Book> {
        let schema_path: Utf8PathBuf = self
            .config
            .schemd_schema
            .as_ref()
            .map(|path| self.ctx.root.join(path).try_into())
            .transpose()?
            .unwrap_or_else(|| "schemd.schema.yml".into());

        let schema = source::RootSchema::from_file(schema_path)?;

        let doc = md_doc::hir::Dom::builder().schema(schema).build()?.lower();

        let mut placeholder = PlaceholderChapter::find(&mut book.sections, ROOT_PLACEHOLDER)
            .with_context(|| {
                format!(
                    "Could not find a draft chapter with the placeholder \
                    '[{ROOT_PLACEHOLDER}]()'. This placeholder must specify a place \
                    where the root documentation of the schema will be output",
                )
            })?;

        let root = mir::NamedDocument::new(&placeholder.name, doc.root);
        Self::replace_draft_chapter(root, placeholder.chapter())?;

        let placeholder = PlaceholderChapter::find(&mut book.sections, TYPE_INDEX_PLACEHOLDER);
        match (doc.type_index, placeholder) {
            (None, None) => {}
            (Some(_), None) => {
                bail!(
                    "The schema has a type index, but no {TYPE_INDEX_PLACEHOLDER} \
                    placeholder was found in SUMMARY.md"
                )
            }
            (None, Some(placeholder)) => placeholder.remove(),
            (Some(document), Some(mut placeholder)) => {
                let document = mir::NamedDocument::new(&placeholder.name, document);
                Self::replace_draft_chapter(document, placeholder.chapter())?;
            }
        }

        if let Ok(path) = std::env::var("SCHEMD_DUMP_BOOK") {
            let book = crate::serdex::json::to_string_pretty(&book);
            let path = if path.trim().is_empty() {
                "./book.json"
            } else {
                path.as_str()
            };

            fs::write(path, book)?;
        }

        Ok(book)
    }

    fn replace_draft_chapter(document: mir::NamedDocument, chapter: &mut book::Chapter) -> Result {
        let section_number = chapter.number.as_mut().with_context(|| {
            format!(
                "Expected a placeholder draft chapter '{}' to be a numbered chapter",
                chapter.name
            )
        })?;
        let section_number = std::mem::take(section_number);

        *chapter = Self::mir_into_mdbook(document, &chapter.parent_names, section_number);

        Ok(())
    }

    fn mir_into_mdbook(
        document: mir::NamedDocument,
        parent_names: &[String],
        section_number: book::SectionNumber,
    ) -> book::Chapter {
        // We convert everything to kebab case to make sure the path is URL friendly
        let doc_name = document.name.to_kebab_case();

        let next_parent_names: Vec<_> = parent_names.iter().cloned().chain([doc_name]).collect();

        let sub_items = document
            .data
            .children
            .into_iter()
            .enumerate()
            .map(|(i, child)| {
                let section_number = section_number.iter().copied().chain([i as u32]).collect();
                let chapter = Self::mir_into_mdbook(child, &next_parent_names, section_number);
                book::BookItem::Chapter(chapter)
            })
            .collect();

        let content = document.data.section.to_markdown(1);

        book::Chapter {
            name: document.name,
            content,
            number: Some(section_number),
            sub_items,
            path: Some(<_>::from_iter(next_parent_names)),
            source_path: None,
            parent_names: parent_names.to_vec(),
        }
    }
}

struct PlaceholderChapter<'book> {
    name: String,
    parent: &'book mut Vec<book::BookItem>,
    index: usize,
}

impl<'book> PlaceholderChapter<'book> {
    fn find(items: &'book mut Vec<BookItem>, placeholder: &str) -> Option<Self> {
        // It is this ugly because of a borrow checker limitation. We can't
        // recursively call `find` in the same loop where we already have a
        // return statement that returns the entire `items` vector in it.
        //
        // The workaround is to split the search by direct children and nested
        // children into two loops
        for (index, item) in items.iter_mut().enumerate() {
            let chapter = match item {
                mdbook::BookItem::Chapter(chapter) => chapter,
                _ => continue,
            };

            if chapter.name.contains(placeholder) {
                let name = chapter.name.replace(placeholder, "").trim().to_owned();
                return Some(Self {
                    name,
                    parent: items,
                    index,
                });
            }
        }

        items.iter_mut().find_map(|item| {
            let chapter = match item {
                mdbook::BookItem::Chapter(chapter) => chapter,
                _ => return None,
            };
            Self::find(&mut chapter.sub_items, placeholder)
        })
    }

    fn chapter(&mut self) -> &mut book::Chapter {
        match &mut self.parent[self.index] {
            BookItem::Chapter(chapter) => chapter,
            _ => unreachable!(),
        }
    }

    fn remove(self) {
        self.parent.remove(self.index);
    }
}

#[derive(Default, Deserialize, Debug)]
struct Config {
    /// Path to file containing the Schemd schema that we need to process.
    /// If a relative path is provided, it is resolved relative to the root of
    /// the config file itself.
    schemd_schema: Option<Utf8PathBuf>,
}

impl Config {
    fn from_ctx(ctx: &PreprocessorContext) -> Result<Config> {
        #[derive(Deserialize, Debug)]
        struct BookToml {
            preprocessor: Option<PreprocessorConfig>,
        }

        #[derive(Deserialize, Debug)]
        struct PreprocessorConfig {
            schemd: Option<Config>,
        }

        // HACK: we read the original `book.toml` file source to provider better
        // error reporting, because `toml::from_str` inserts code snippets and
        // line numbers in the error messages this way. This is in contrast to
        // deserializing the config from a dynamic `toml::Map` already present
        // in PreprocessorContext, which would not provide such nice error messages
        let path = ctx.root.join("book.toml");
        let config = fs::read_to_string(path)?;

        let config: BookToml = toml::from_str(&config)?;

        let config = config
            .preprocessor
            .and_then(|preprocessor| preprocessor.schemd)
            .unwrap_or_default();

        Ok(config)
    }
}

// pub(crate) fn gen(root: &schemd_schema::RootSchema) -> Result<()> {
//     let out_dir = "docs/src/checks2";

//     let header = "config";
//     let body = "\
// The top level config for cargo-deny, by default called `deny.toml`.

// ## Example - cargo-deny's own configuration

// ```ini
// {{#include ../../../deny.toml}}
// ```";

//     let renderer = Renderer {
//         root_file_base: Section::leaf(header, body),
//     };

//     let options = DocOptions {
//         root: root.clone(),
//         max_nesting_in_file: 2,
//     };

//     let files = renderer.doc(&Doc::new(options)?);

//     files.iter().try_for_each(|file| file.write(out_dir))?;

//     Ok(())
// }
