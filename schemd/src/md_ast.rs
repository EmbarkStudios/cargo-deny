use itertools::Either;
use pulldown_cmark::{CowStr, Event, LinkType, Tag};

const SPECIAL_CHARS: &str = "#\\_*<>`|[]";

pub(crate) enum MdNode<'a> {
    Many(Vec<Self>),

    Code(CowStr<'a>),

    Text(CowStr<'a>),

    Link {
        label: Vec<Self>,
        url: CowStr<'a>,
    },

    List {
        children: Vec<Self>,

        /// Defines the start number for an ordered list.
        /// If [`None`] it is an unordered list.
        start: Option<u64>,
    },

    Paragraph {
        children: Vec<Self>,
    },
}

impl<'a> MdNode<'a> {
    fn for_each_pulldown_cmark_event(&'a self, visit: &mut dyn FnMut(Event<'a>)) {
        match self {
            MdNode::Many(nodes) => {
                for node in nodes {
                    node.for_each_pulldown_cmark_event(visit);
                }
            }
            MdNode::Code(code) => {
                visit(Event::Code(CowStr::Borrowed(code)));
            }
            MdNode::Text(text) => {
                visit(Event::Text(escape(text)));
            }
            MdNode::Link { label, url } => {
                let link = TagGuard::new(
                    visit,
                    Tag::Link {
                        link_type: LinkType::Inline,
                        dest_url: CowStr::Borrowed(url),
                        title: "".into(),
                        id: "".into(),
                    },
                );

                for node in label {
                    node.for_each_pulldown_cmark_event(link.visit);
                }
            }
            MdNode::List { children, start } => {
                if children.is_empty() {
                    return;
                }

                // let tag = Tag::List(*start);
                // let end = tag.to_end();
                // visit(Event::Start(tag));

                let mut list = TagGuard::new(visit, Tag::List(*start));

                for node in children {
                    // let item = TagGuard::new(list.visit, Tag::Item);

                    let item = list.nest(Tag::Item);
                    // let tag = Tag::Item;
                    // let end = tag.to_end();
                    // visit(Event::Start(tag));

                    node.for_each_pulldown_cmark_event(item.visit);

                    // visit(Event::End(end));
                }

                // visit(Event::End(end));
            }
            MdNode::Paragraph { children } => {
                let paragraph = TagGuard::new(visit, Tag::Paragraph);
                for node in children {
                    node.for_each_pulldown_cmark_event(paragraph.visit);
                }
            }
        }
    }

    pub(crate) fn to_markdown(&self) -> String {
        let options = pulldown_cmark_to_cmark::Options {
            list_token: '-',
            ..Default::default()
        };

        let mut buf = String::new();
        let mut state = None;

        self.for_each_pulldown_cmark_event(&mut |event| {
            let events = [event].into_iter();
            let new_state = pulldown_cmark_to_cmark::cmark_resume_with_options(
                events,
                &mut buf,
                state.take(),
                options.clone(),
            )
            .expect("Writing to String should not fail");
            state = Some(new_state);
        });

        buf
    }

    pub(crate) fn many(nodes: impl IntoIterator<Item = Self>) -> Self {
        MdNode::Many(Vec::from_iter(nodes))
    }

    pub(crate) fn code(code: impl Into<CowStr<'a>>) -> Self {
        MdNode::Code(code.into())
    }

    pub(crate) fn text(text: impl Into<CowStr<'a>>) -> Self {
        MdNode::Text(text.into())
    }

    pub(crate) fn link(label: impl IntoIterator<Item = Self>, url: impl Into<CowStr<'a>>) -> Self {
        MdNode::Link {
            label: Vec::from_iter(label),
            url: url.into(),
        }
    }

    pub(crate) fn unordered_list(items: impl IntoIterator<Item = Self>) -> Self {
        MdNode::List {
            children: Vec::from_iter(items),
            start: None,
        }
    }

    pub(crate) fn paragraph(content: impl IntoIterator<Item = Self>) -> Self {
        MdNode::Paragraph {
            children: Vec::from_iter(content),
        }
    }
}

pub(crate) fn escape(input: &impl AsRef<str>) -> CowStr<'_> {
    let input = input.as_ref();

    // Optimization when no escaping is needed
    if input.chars().all(|c| !SPECIAL_CHARS.contains(c)) {
        return input.into();
    }

    input
        .chars()
        .flat_map(|char| {
            if SPECIAL_CHARS.contains(char) {
                Either::Left(['\\', char].into_iter())
            } else {
                Either::Right([char].into_iter())
            }
        })
        .collect::<String>()
        .into()
}

struct TagGuard<'e, 'v> {
    end: Option<Event<'e>>,
    visit: &'v mut dyn FnMut(Event<'e>),
}

impl Drop for TagGuard<'_, '_> {
    fn drop(&mut self) {
        (self.visit)(self.end.take().unwrap());
    }
}

impl<'e, 'v> TagGuard<'e, 'v> {
    #[must_use]
    fn new(visit: &'v mut dyn FnMut(Event<'e>), start: Tag<'e>) -> Self {
        let end = start.to_end();
        visit(Event::Start(start));

        Self {
            end: Some(Event::End(end)),
            visit,
        }
    }

    fn visit(&mut self, event: Event<'e>) {
        (self.visit)(event);
    }

    fn nest(&mut self, start: Tag<'e>) -> TagGuard<'e, '_> {
        TagGuard::new(&mut *self.visit, start)
    }
}
