"""Strip the identifying structure out of a real issue.

PROJECT_SPEC.md §6.1 authorises reading real issue text for the false-positive
measurement, and this is the first half of what that authorisation is
conditional on. The second half is a review pass over the prose, in
`tools/fetch_real_corpus.py`, which drops an issue entirely rather than trying
to scrub it.

The split is deliberate. What this module does is mechanical and therefore
checkable: an email address has a shape, a `@mention` has a shape, a home
directory path has a shape. What it cannot do is find a person's name in a
sentence — a name list misses uncommon names and destroys ordinary words, since
someone is called Mark and `mark` is also a verb. Pretending otherwise is how a
de-identifier becomes a false reassurance.

So this module is honest about its scope: it removes the fields and patterns
that carry identity by construction, and `residual_risks()` names what it
leaves behind, so the caller cannot mistake a clean pass for a clean issue.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass

# An @mention. Underscores are allowed even though GitHub handles cannot
# contain them, because the field these come from is not always GitHub.
#
# The first version used GitHub's own shape — alphanumeric and hyphen — and
# `@dongxi_nlp` then matched *nothing at all*: the class stopped at the
# underscore and the trailing `\b` could not match between `i` and `_`, since
# `_` is a word character. So the regex backtracked to failure and the whole
# handle passed through untouched. Twitter and X handles allow underscores and
# langchain's issue template has a social-handles field, so this was a live
# leak path. The review pass happened to drop every issue carrying one, which
# is the second layer covering the first layer's bug rather than the first
# layer working.
MENTION = re.compile(r"(?<![\w.])@([A-Za-z0-9][A-Za-z0-9_-]{0,38})(?![\w-])")

# Already scrubbed. Without this, re-processing a record hashes the pseudonym
# again and the same author stops mapping to the same handle — which matters
# because the fetcher is resumable and may see a record twice.
PSEUDONYM = re.compile(r"^reporter-[0-9a-f]{6}$")

# Fenced and inline code. Decorators live here, mentions do not, so mention
# scrubbing skips these spans wholesale. Emails, URLs and home paths are still
# scrubbed inside code — a traceback carrying `/Users/sarahchen/` is exactly
# the case that must not survive.
CODE_SPAN = re.compile(r"```.*?```|`[^`\n]*`", re.S)

# `@word` that is language syntax rather than a person. Needed on top of the
# code-span rule because real issues paste decorators into prose without
# fencing them, and a first version of this module turned every `@property` in
# a pandas issue into a pseudonym.
#
# Incomplete by construction — that is why it is a second line of defence
# rather than the only one, and why the bias is to scrub: a surviving handle is
# a privacy failure, a scrubbed decorator is a data-quality one.
NOT_A_HANDLE = frozenset(
    {
        "property", "staticmethod", "classmethod", "abstractmethod",
        "abstractproperty", "cached_property", "dataclass", "dataclasses",
        "functools", "wraps", "singledispatch", "lru_cache", "cache",
        "override", "overload", "final", "runtime_checkable",
        "pytest", "fixture", "mark", "parametrize", "parameterized", "patch",
        "mock", "given", "settings", "example",
        "media", "import", "keyframes", "supports", "charset", "namespace",
        "param", "params", "returns", "return", "throws", "raises", "type",
        "deprecated", "since", "author", "see", "link", "code",
        "Override", "Test", "Before", "After", "BeforeEach", "AfterEach",
        "Component", "Injectable", "NgModule", "Input", "Output", "Bean",
        "app", "task", "route", "get", "post", "put", "delete", "command",
        "staticfiles", "everyone", "here", "all", "channel",
    }
)

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Home directories, which carry the account name on all three platforms.
HOME_PATH = re.compile(
    r"(?i)(/(?:home|Users)/|[A-Za-z]:\\Users\\\\?|\\\\Users\\\\)([^/\\\s\"'<>|]+)"
)

# A URL. Kept as a host-only stub rather than deleted, because "there was a
# link here" is information a triage model legitimately reacts to, while the
# path and query are where the identifying parts live.
URL = re.compile(r"https?://([A-Za-z0-9.-]+)(/[^\s)\]}>\"']*)?")

# GitHub's own noise: the signature it appends to issues created from a
# template, and the reply-quote header carrying a real name and timestamp.
QUOTE_HEADER = re.compile(
    r"(?m)^On .{0,40}\d{4}.{0,40}(?:wrote|schrieb|escribió):\s*$"
)

# --- Credentials -----------------------------------------------------------
#
# People paste API keys into issues by accident. It is common enough that
# GitHub runs secret scanning for it, and a repository whose issues are about
# calling paid APIs is the likeliest place of all to find one.
#
# PROJECT_SPEC.md §6 rule 3 forbids real credentials absolutely, and §6.1
# relaxes nothing about it. So this is not a nicety: a real key reaching the
# corpus would be written to disk and sent to a model provider, and either is a
# straight violation. The de-identifier had no credential rule at all until a
# langchain fetch was about to run.
#
# Two arms, and one definition shared with the corpus gates so they cannot
# drift: a known vendor prefix, or an assignment to a secret-ish name whose
# value actually looks like a secret.
VENDOR_PREFIXED = re.compile(
    r"\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9_-]{11,}"
    r"|\b(?:ghp|gho|ghs|ghu|ghr|github_pat)_[A-Za-z0-9_]{12,}"
    r"|\bxox[abpsr]-[A-Za-z0-9-]{12,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}"
    r"|\bhf_[A-Za-z0-9]{20,}"
    r"|\bglpat-[A-Za-z0-9_-]{16,}"
)

SECRET_ASSIGNMENT = re.compile(
    r"(\b\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY)\w*\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)

# Values that follow a secret-ish name but are plainly not secrets:
# placeholders, masks, booleans, paths, and comma-separated name lists.
NOT_A_SECRET = re.compile(
    r"^(?:\[|<|\*|\"|'|\$|%|/|\.|~|\{|`)"
    r"|^(?:redacted|masked|hidden|none|null|nil|true|false|yes|no|unset|empty"
    r"|your|my|xxx+|todo|placeholder)\b"
    r"|,",
    re.IGNORECASE,
)

REDACTED = "[redacted-credential]"


def _is_secret_value(value: str) -> bool:
    """Does the value after a secret-ish name actually look like a secret?

    Length, no obvious placeholder, and a mix of letters and digits — a real
    token has both, while an all-letter value is a word: a filename, a mode, an
    identifier. Filtering here rather than in the pattern is what keeps
    `key=[redacted]` (an issue *about* redaction) and
    `config_keys_overridden=retries,log_level` (a list of names) from being
    treated as leaks.
    """
    value = value.strip().strip("'\"`,;)>")
    if len(value) < 12 or NOT_A_SECRET.match(value):
        return False
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def credential_shaped(text: str) -> list[str]:
    """Strings in `text` that could be mistaken for a live credential.

    The one definition, shared by the scrubber and by the corpus gates. Two
    copies of "what looks like a secret" would drift, and the copy that drifted
    would be the one deciding whether a real key reached disk.
    """
    found = [m.group(0) for m in VENDOR_PREFIXED.finditer(text)]
    found += [
        m.group(0)
        for m in SECRET_ASSIGNMENT.finditer(text)
        if _is_secret_value(m.group(2))
    ]
    return found


def redact_credentials(text: str) -> str:
    """Replace credential-shaped strings, keeping the shape that isn't secret.

    `MY_API_KEY=abc123...` becomes `MY_API_KEY=[redacted-credential]`: a triage
    model legitimately reacts to "there is a key here", and that signal is not
    the secret. Same reasoning as stubbing a URL's path but keeping its host.
    """
    text = VENDOR_PREFIXED.sub(REDACTED, text)

    def redact_assignment(match: re.Match[str]) -> str:
        if not _is_secret_value(match.group(2)):
            return match.group(0)
        return match.group(1) + REDACTED

    return SECRET_ASSIGNMENT.sub(redact_assignment, text)


@dataclass(frozen=True)
class Deidentified:
    """One issue with its mechanical identifiers removed."""

    issue_id: str
    title: str
    author: str
    body: str
    removed: tuple[str, ...]
    """What was taken out, by kind, for the audit trail."""

    @property
    def changed(self) -> bool:
        return bool(self.removed)


def pseudonym(handle: str) -> str:
    """A stable synthetic handle for a real one.

    Stable so the same author reads as the same author across issues — a real
    backlog has repeat reporters and flattening them all to one name would
    change the shape of the data. Derived by hash rather than a counter so it
    does not depend on fetch order, and truncated so it cannot be reversed by
    anything short of guessing the input.
    """
    digest = hashlib.sha256(handle.encode("utf-8")).hexdigest()[:6]
    return f"reporter-{digest}"


def _outside_code(text: str, transform: Callable[[str], str]) -> str:
    """Apply `transform` to every part of `text` that is not a code span.

    Splitting rather than trying to write one regex that understands markdown:
    a fenced block can contain anything, including text that looks exactly
    like a mention, and the only reliable way to leave it alone is to not look
    inside it.
    """
    pieces: list[str] = []
    cursor = 0
    for span in CODE_SPAN.finditer(text):
        pieces.append(transform(text[cursor : span.start()]))
        pieces.append(span.group(0))
        cursor = span.end()
    pieces.append(transform(text[cursor:]))
    return "".join(pieces)


def scrub(text: str) -> tuple[str, list[str]]:
    """Remove the patterns that carry identity by construction.

    Each rule is noted only if it actually changed the text, not merely if it
    matched. The difference shows up on a second pass: `/home/[user]/x` still
    *matches* the home-path rule and rewriting it is a no-op, so a match-based
    audit trail would report a removal that did not happen. `removed` is the
    record of what was taken out of a real issue, and it has to be true.
    """
    removed: list[str] = []

    def apply(kind: str, transform: Callable[[str], str], current: str) -> str:
        after = transform(current)
        if after != current and kind not in removed:
            removed.append(kind)
        return after

    def replace_mention(match: re.Match[str]) -> str:
        handle = match.group(1)
        if handle in NOT_A_HANDLE or PSEUDONYM.match(handle):
            return match.group(0)
        return "@" + pseudonym(handle)

    def url_stub(match: re.Match[str]) -> str:
        host = match.group(1)
        return f"https://{host}/[path]" if match.group(2) else f"https://{host}"

    # Credentials first, and everywhere including code spans: a leaked key is
    # most often inside a pasted config block or traceback, which is exactly
    # what the mention rule deliberately does not look inside.
    text = apply("credential", redact_credentials, text)
    text = apply("email", lambda s: EMAIL.sub("[email]", s), text)
    text = apply(
        "quote_header", lambda s: QUOTE_HEADER.sub("[quoted reply]", s), text
    )
    text = apply(
        "mention",
        lambda s: _outside_code(s, lambda part: MENTION.sub(replace_mention, part)),
        text,
    )
    text = apply(
        "home_path",
        lambda s: HOME_PATH.sub(lambda m: m.group(1) + "[user]", s),
        text,
    )
    text = apply("url", lambda s: URL.sub(url_stub, s), text)

    return text, removed


def deidentify(
    *, issue_id: str, title: str, author: str, body: str
) -> Deidentified:
    """Strip a raw issue. The author field always goes; the rest is by pattern."""
    clean_title, title_removed = scrub(title)
    clean_body, body_removed = scrub(body)
    removed = ["author"] + [
        kind for kind in (*title_removed, *body_removed) if kind
    ]
    # Preserve order, drop repeats.
    seen: list[str] = []
    for kind in removed:
        if kind not in seen:
            seen.append(kind)
    return Deidentified(
        issue_id=issue_id,
        title=clean_title,
        author=pseudonym(author),
        body=clean_body,
        removed=tuple(seen),
    )


def residual_risks() -> tuple[str, ...]:
    """What this module knowingly leaves in the text.

    Returned rather than written in a comment so the fetcher can print it every
    run. A de-identifier whose limits are only documented gets remembered as
    one without limits.
    """
    return (
        "a person's name written in prose ('Mira also saw this')",
        "an employer or customer named in prose ('our cluster at Acme')",
        "a distinctive setup that identifies one organisation even unnamed",
        "writing style, which is weakly identifying on its own",
        "a name embedded in a path segment that is not a home directory",
        "a credential with no recognised vendor prefix and no secret-ish "
        "variable name beside it — a bare high-entropy string is "
        "indistinguishable from a hash, an id, or base64 data",
    )
