//!
//! Detects reads of `document.referrer`, which is attacker-controlled: a
//! malicious page can create a link or redirect to the target, making
//! `document.referrer` contain an attacker-chosen URL. Flagged as **input**
//! source.

use oxc_ast::AstKind;

use crate::ctx::{Category, RawMatch};
use crate::utils::is_document_object;

use super::member_parts;

pub fn check(kind: AstKind, out: &mut Vec<RawMatch>) {
    let Some((prop_name, object, span)) = member_parts(kind) else {
        return;
    };
    if prop_name != "referrer" {
        return;
    }
    if !is_document_object(object) {
        return;
    }
    out.push(RawMatch {
        detector: "documentReferrer",
        category: Category::Input,
        span,
    });
}
