/**
 * List sizing conventions.
 *
 * Goal: **no page-level scrollbar**; list height and header are fixed, and overflowing
 * data scrolls inside the list body.
 *
 * Division of labour:
 * - Height: `.page-fill` lets the page header + card fill the content area, `.list-card`
 *   flexes its children, and `.ant-table-body` gets overflow-y:auto (see styles.css).
 * - Trigger: the table must receive `scroll={{ y: ... }}` so rc-table splits the header
 *   and body into two containers; the numeric y is overridden by CSS `max-height:none`
 *   and the real height is whatever space the card has left.
 * - The page length is fixed and does not change with viewport height, so card height
 *   never jumps.
 */
export const LIST_ROW_HEIGHT = 52

export const LIST_PAGE_SIZE = 12

/** Placeholder for the table's scroll.y: only makes antd split header/body; CSS controls the real height. */
export const LIST_SCROLL_Y = 400
