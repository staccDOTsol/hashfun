"""Launch metadata: the picture, the blurb, the links.

None of it is consensus data and the node never reads it. The descriptor commits to it with one
field, `meta` = SHA256 of the canonical bytes below. That field is hashed into the launch id and
the genesis coinbase pushes the launch id, so the genesis block pins the picture: it cannot be
swapped after launch, by the creator or by a site showing it. The bytes ride in the launch file
under "metadata" (every node needs that file to join the chain, so everyone on the chain has
them). Anything that shows a coin's picture checks it against the hash first: check().

  canonical = "hashfun-meta\\x01" || vs(description) || vs(image_type) || vs(image)
              || vs(website) || vs(x) || vs(telegram)          (vs = Bitcoin varint length + bytes)

hashfun/web/src/btc.js (metaHash) mirrors this byte for byte; tests/test_web_js.py checks it."""
import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional

from .crypto import sha256
from .ser import varint

TAG = b"hashfun-meta\x01"
MAX_IMAGE = 65536
MAX_DESCRIPTION = 500  # bytes of UTF-8
MAX_LINK = 200
LINKS = ("website", "x", "telegram")
_LINK = re.compile(r"https://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+")


class MetaError(ValueError):
    pass


def image_type_of(data: bytes) -> Optional[str]:
    """The type a picture's own bytes say it is. SVG is refused on purpose: it can carry script."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


@dataclass
class Meta:
    description: str = ""
    image_type: str = ""
    image: bytes = b""
    website: str = ""
    x: str = ""
    telegram: str = ""

    def canonical(self) -> bytes:
        def vs(b: bytes) -> bytes:
            return varint(len(b)) + b
        return TAG + vs(self.description.encode()) + vs(self.image_type.encode()) + vs(self.image) + \
            b"".join(vs(getattr(self, k).encode()) for k in LINKS)

    def hash(self) -> bytes:
        return sha256(self.canonical())

    def empty(self) -> bool:
        return not (self.description or self.image or any(getattr(self, k) for k in LINKS))

    def validate(self):
        try:
            n = len(self.description.encode())
        except UnicodeEncodeError:
            raise MetaError("description: invalid text")
        if n > MAX_DESCRIPTION:
            raise MetaError(f"description: at most {MAX_DESCRIPTION} bytes")
        if any(ord(c) < 32 and c != "\n" for c in self.description):
            raise MetaError("description: control characters")
        if len(self.image) > MAX_IMAGE:
            raise MetaError(f"image: at most {MAX_IMAGE} bytes (this one is {len(self.image)})")
        if self.image:
            kind = image_type_of(self.image)
            if kind is None:
                raise MetaError("image: PNG, JPEG, GIF or WebP only")
            if self.image_type != kind:
                raise MetaError(f"image_type: the bytes are {kind}")
        elif self.image_type:
            raise MetaError("image_type: set without an image")
        for k in LINKS:
            v = getattr(self, k)
            if v and (len(v) > MAX_LINK or not _LINK.fullmatch(v)):
                raise MetaError(f"{k}: an https:// link of at most {MAX_LINK} characters")

    def to_json(self) -> dict:
        o = {"description": self.description, "image_type": self.image_type,
             "image": base64.b64encode(self.image).decode(), **{k: getattr(self, k) for k in LINKS}}
        return {k: v for k, v in o.items() if v}

    @classmethod
    def from_json(cls, o) -> "Meta":
        if not isinstance(o, dict):
            raise MetaError("metadata: expected an object")
        vals = {}
        for k in ("description", "image_type", "image") + LINKS:
            v = o.get(k, "")
            if not isinstance(v, str):
                raise MetaError(f"{k}: expected a string")
            vals[k] = v
        try:
            vals["image"] = base64.b64decode(vals["image"], validate=True)
        except (binascii.Error, ValueError):
            raise MetaError("image: invalid base64")
        m = cls(**vals)
        m.validate()
        return m


def from_image(data: bytes, **kw) -> Meta:
    m = Meta(image=data, image_type=image_type_of(data) or "", **kw)
    m.validate()
    return m


def attach(d, m: Meta):
    """Commit a launch to its metadata. Changes the launch id: do it before grinding genesis."""
    m.validate()
    if m.empty():
        d.meta, d.metadata = bytes(32), None
    else:
        d.meta, d.metadata = m.hash(), m.to_json()


def check(d) -> Optional[Meta]:
    """The launch's metadata if it has any and the bytes match the hash in the descriptor.
    None when the launch has none, or commits to some but the file does not carry them.
    Raises MetaError when the file carries bytes that are not the committed ones."""
    if not any(d.meta):
        if d.metadata:
            raise MetaError("the launch file carries metadata the descriptor does not commit to")
        return None
    if not d.metadata:
        return None
    m = Meta.from_json(d.metadata)
    if m.hash() != d.meta:
        raise MetaError("metadata does not match the hash in the descriptor")
    return m
