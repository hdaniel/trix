import BasicObject from "trix/core/basic_object"

import { nodeIsAttachmentElement, removeNode, tagName, walkTree } from "trix/core/helpers"
import DOMPurify from "dompurify"
import * as config from "trix/config"

DOMPurify.addHook("uponSanitizeAttribute", function (node, data) {
  const allowedAttributePattern = /^data-trix-/
  if (allowedAttributePattern.test(data.attrName)) {
    data.forceKeepAttr = true
  }
})

const DEFAULT_ALLOWED_ATTRIBUTES = "style href src width height language class".split(" ")
const DEFAULT_FORBIDDEN_PROTOCOLS = "javascript:".split(" ")
const DEFAULT_FORBIDDEN_ELEMENTS = "script iframe form noscript".split(" ")

export default class HTMLSanitizer extends BasicObject {
  static setHTML(element, html, options) {
    const sanitizedElement = new this(html, options).sanitize()
    const sanitizedHtml = sanitizedElement.getHTML ? sanitizedElement.getHTML() : sanitizedElement.outerHTML
    element.innerHTML = sanitizedHtml
  }

  static sanitize(html, options) {
    const sanitizer = new this(html, options)
    sanitizer.sanitize()
    return sanitizer
  }

  constructor(html, { allowedAttributes, forbiddenProtocols, forbiddenElements, purifyOptions } = {}) {
    super(...arguments)
    this.allowedAttributes = allowedAttributes || DEFAULT_ALLOWED_ATTRIBUTES
    this.forbiddenProtocols = forbiddenProtocols || DEFAULT_FORBIDDEN_PROTOCOLS
    this.forbiddenElements = forbiddenElements || DEFAULT_FORBIDDEN_ELEMENTS
    this.purifyOptions = purifyOptions || {}
    this.body = createBodyElementForHTML(html)
  }

  sanitize() {
    this.sanitizeElements()
    this.normalizeListElementNesting()
    const purifyConfig = Object.assign({}, config.dompurify, this.purifyOptions)
    // Note: DOMPurify strips <iframe> by default. Some distributions (e.g.,
    // Action Text’s packaged build) set ADD_TAGS: ["iframe"] in the DOMPurify
    // config to preserve trusted embeds like video players. This is optional and
    // should only be enabled if you are certain the iframe sources are trusted.
    // See action_text-trix/app/assets/javascripts/trix.js for an example.
    DOMPurify.setConfig(purifyConfig)
    this.body = DOMPurify.sanitize(this.body)

    return this.body
  }

  getHTML() {
    return this.body.innerHTML
  }

  getBody() {
    return this.body
  }

  // Private

  sanitizeElements() {
    const walker = walkTree(this.body)
    const nodesToRemove = []

    while (walker.nextNode()) {
      const node = walker.currentNode
      switch (node.nodeType) {
        case Node.ELEMENT_NODE:
          if (this.elementIsRemovable(node)) {
            nodesToRemove.push(node)
          } else {
            this.sanitizeElement(node)
          }
          break
        case Node.COMMENT_NODE:
          nodesToRemove.push(node)
          break
      }
    }

    nodesToRemove.forEach((node) => removeNode(node))

    return this.body
  }

  sanitizeElement(element) {
    // Keep minimal protocol safety for href; DOMPurify also handles this.
    if (element.hasAttribute("href")) {
      if (this.forbiddenProtocols.includes(element.protocol)) {
        element.removeAttribute("href")
      }
    }

    // Do not remove attributes here. Let DOMPurify handle attribute allow/deny,
    // while a DOMPurify hook above preserves data-trix-* attributes.
    return element
  }

  normalizeListElementNesting() {
    Array.from(this.body.querySelectorAll("ul,ol")).forEach((listElement) => {
      const previousElement = listElement.previousElementSibling
      if (previousElement) {
        if (tagName(previousElement) === "li") {
          previousElement.appendChild(listElement)
        }
      }
    })

    return this.body
  }

  elementIsRemovable(element) {
    if (element?.nodeType !== Node.ELEMENT_NODE) return
    // Only remove elements that should not be serialized by Trix;
    // leave tag allow/deny decisions to DOMPurify.
    return this.elementIsntSerializable(element)
  }

  elementIsntSerializable(element) {
    return element.getAttribute("data-trix-serialize") === "false" && !nodeIsAttachmentElement(element)
  }
}

const createBodyElementForHTML = function(html = "") {
  // Remove everything after </html>
  html = html.replace(/<\/html[^>]*>[^]*$/i, "</html>")
  const doc = document.implementation.createHTMLDocument("")
  doc.documentElement.innerHTML = html

  Array.from(doc.head.querySelectorAll("style")).forEach((element) => {
    doc.body.appendChild(element)
  })

  return doc.body
}
