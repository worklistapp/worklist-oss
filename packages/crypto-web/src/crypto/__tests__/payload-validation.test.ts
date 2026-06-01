import { describe, expect, it } from 'vitest'
import { encode as cborEncode } from 'cbor-x'

import { PayloadValidationError, validatePayloadBytes } from '../payload-validation'

const SAMPLE_UUID = '00000000-0000-0000-0000-000000000001'

function encodeEnvelope(envelope: Record<string, unknown>): Uint8Array {
  return new Uint8Array(cborEncode(envelope))
}

describe('validatePayloadBytes', () => {
  it('accepts a valid work list envelope', () => {
    const envelope = {
      kind: 'work_list',
      version: 1,
      body: {
        title: 'Inbox',
        description: 'default description',
        theme: { color: '#112233', emoji: '🔥' },
        sections: [
          { id: SAMPLE_UUID, name: 'Doing', wip_limit: 2 },
          { id: '00000000-0000-0000-0000-000000000002', name: 'Done', wip_limit: null },
        ],
        client_meta: { 'web.view': { layout: 'kanban' } },
      },
    }

    const bytes = encodeEnvelope(envelope)
    expect(() => validatePayloadBytes(bytes, 'work_list')).not.toThrow()
  })

  it('rejects work list envelopes with too many sections', () => {
    const sections = Array.from({ length: 40 }, (_, index) => ({
      id: `00000000-0000-0000-0000-${(index + 1).toString().padStart(12, '0')}`,
      name: `Section ${index + 1}`,
      wip_limit: 1,
    }))
    const envelope = {
      kind: 'work_list',
      version: 1,
      body: {
        title: 'Overflow',
        sections,
        client_meta: {},
      },
    }

    const bytes = encodeEnvelope(envelope)
    expect(() => validatePayloadBytes(bytes, 'work_list')).toThrow(
      /sections cannot exceed/i,
    )
  })

  it('rejects task envelopes with oversized attachments', () => {
    const envelope = {
      kind: 'task',
      version: 1,
      body: {
        title: 'Ship release',
        attachments: [
          {
            id: SAMPLE_UUID,
            file_name: 'oversized.bin',
            content_type: 'application/octet-stream',
            size_bytes: 10 * 1024 * 1024 + 1,
            blob_key: new Uint8Array([1, 2, 3]),
          },
        ],
        checklist: [],
        references: [],
        client_meta: {},
      },
    }

    const bytes = encodeEnvelope(envelope)
    expect(() => validatePayloadBytes(bytes, 'task')).toThrow(/attachments\.size_bytes/i)
  })

  it('rejects mismatched payload kinds', () => {
    const envelope = {
      kind: 'work_list',
      version: 1,
      body: {
        title: 'Inbox',
        sections: [],
        client_meta: {},
      },
    }

    const bytes = encodeEnvelope(envelope)
    expect(() => validatePayloadBytes(bytes, 'task')).toThrow(PayloadValidationError)
  })

  it('rejects unsupported schema versions', () => {
    const envelope = {
      kind: 'comment',
      version: 2,
      body: {
        content: {
          format: 'markdown',
          version: 1,
          blocks: [{ type: 'paragraph', text: 'Hello' }],
        },
        attachments: [],
        mentions: [],
      },
    }

    const bytes = encodeEnvelope(envelope)
    expect(() => validatePayloadBytes(bytes, 'comment')).toThrow(/not supported/i)
  })

  describe('note payload validation', () => {
    it('accepts a valid note envelope', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'My Note',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [{ type: 'paragraph', text: 'Hello world' }],
          },
          mentions: [SAMPLE_UUID],
          attachments: [],
          client_meta: { 'web.editor': 'prosemirror' },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).not.toThrow()
    })

    it('accepts note with empty blocks array', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Empty Note',
          content: {
            format: 'plaintext',
            version: 1,
            blocks: [],
          },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).not.toThrow()
    })

    it('rejects note without title', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/title must be a string/i)
    })

    it('rejects note with empty title', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: '',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/title must have at least 1/i)
    })

    it('rejects note without content', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Missing content',
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/content must be an object/i)
    })

    it('rejects note with invalid content format', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Bad format',
          content: {
            format: 'html', // not allowed
            version: 1,
            blocks: [],
          },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/content\.format must be/i)
    })

    it('rejects note with invalid content version', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Bad version',
          content: {
            format: 'prosemirror',
            version: 2,
            blocks: [],
          },
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/content\.version must be 1/i)
    })

    it('rejects note with too many mentions', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Too many mentions',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
          mentions: Array.from({ length: 60 }, (_, i) =>
            `00000000-0000-0000-0000-${(i + 1).toString().padStart(12, '0')}`,
          ),
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/mentions cannot exceed/i)
    })

    it('rejects note with invalid mention UUID', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Bad mention',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
          mentions: ['not-a-uuid'],
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/mentions\[0\]/i)
    })

    it('rejects note with oversized attachment', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'With attachment',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
          attachments: [
            {
              id: SAMPLE_UUID,
              name: 'huge.bin',
              size: 10 * 1024 * 1024 + 1, // over 10MB limit
              mime_type: 'application/octet-stream',
            },
          ],
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/attachments\[0\]\.size/i)
    })

    it('rejects note attachment with invalid UUID', () => {
      const envelope = {
        kind: 'note',
        version: 1,
        body: {
          title: 'Bad attachment id',
          content: {
            format: 'prosemirror',
            version: 1,
            blocks: [],
          },
          attachments: [
            {
              id: 'not-valid',
              name: 'file.pdf',
              size: 1024,
            },
          ],
        },
      }

      const bytes = encodeEnvelope(envelope)
      expect(() => validatePayloadBytes(bytes, 'note')).toThrow(/attachments\[0\]\.id/i)
    })

    it('accepts note with all supported content formats', () => {
      for (const format of ['plaintext', 'markdown', 'prosemirror']) {
        const envelope = {
          kind: 'note',
          version: 1,
          body: {
            title: `${format} note`,
            content: {
              format,
              version: 1,
              blocks: [],
            },
          },
        }

        const bytes = encodeEnvelope(envelope)
        expect(() => validatePayloadBytes(bytes, 'note')).not.toThrow()
      }
    })
  })
})
