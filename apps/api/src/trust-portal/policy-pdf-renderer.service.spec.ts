import { PolicyPdfRendererService } from './policy-pdf-renderer.service';

describe('PolicyPdfRendererService', () => {
  let service: PolicyPdfRendererService;

  beforeEach(() => {
    service = new PolicyPdfRendererService();
  });

  describe('renderPoliciesPdfBuffer', () => {
    it('returns a valid PDF buffer for a simple policy', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Privacy Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', text: 'We respect your privacy.' }],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
      expect(result.subarray(0, 5).toString()).toBe('%PDF-');
    });

    it('handles multiple policies', () => {
      const policies = [
        {
          name: 'Policy A',
          content: {
            type: 'doc',
            content: [
              {
                type: 'paragraph',
                content: [{ type: 'text', text: 'Content A' }],
              },
            ],
          },
        },
        {
          name: 'Policy B',
          content: {
            type: 'doc',
            content: [
              {
                type: 'paragraph',
                content: [{ type: 'text', text: 'Content B' }],
              },
            ],
          },
        },
      ];

      const result = service.renderPoliciesPdfBuffer(policies, 'Test Org');

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('handles empty content', () => {
      const result = service.renderPoliciesPdfBuffer(
        [{ name: 'Empty Policy', content: null }],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
    });

    it('handles policies without organization name', () => {
      const result = service.renderPoliciesPdfBuffer([
        {
          name: 'Standalone Policy',
          content: {
            type: 'doc',
            content: [
              {
                type: 'paragraph',
                content: [{ type: 'text', text: 'Standalone content.' }],
              },
            ],
          },
        },
      ]);

      expect(result).toBeInstanceOf(Buffer);
    });

    it('handles rich content with headings, bold, lists', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Rich Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'heading',
                  attrs: { level: 1 },
                  content: [{ type: 'text', text: 'Section 1' }],
                },
                {
                  type: 'paragraph',
                  content: [
                    {
                      type: 'text',
                      text: 'Bold text',
                      marks: [{ type: 'bold' }],
                    },
                  ],
                },
                {
                  type: 'bulletList',
                  content: [
                    {
                      type: 'listItem',
                      content: [
                        {
                          type: 'paragraph',
                          content: [{ type: 'text', text: 'Item 1' }],
                        },
                      ],
                    },
                    {
                      type: 'listItem',
                      content: [
                        {
                          type: 'paragraph',
                          content: [{ type: 'text', text: 'Item 2' }],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('handles emoji characters without producing garbled output', () => {
      // Regression test for CS-191: flag emojis like 🇬🇧🇫🇷 were rendered as
      // garbled text "Ø<ÝìØ<Ýç +þ" because Helvetica can't render emojis
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Policy with Emojis',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'paragraph',
                  content: [
                    {
                      type: 'text',
                      text: '🇬🇧🇫🇷 English version available bellow',
                    },
                  ],
                },
                {
                  type: 'paragraph',
                  content: [
                    {
                      type: 'text',
                      text: '🎉 Welcome to our policy 🌍',
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
      expect(result.subarray(0, 5).toString()).toBe('%PDF-');

      // Verify the PDF text does NOT contain garbled emoji byte sequences
      const pdfText = result.toString('latin1');
      expect(pdfText).not.toContain('Ø<Ýì');
      expect(pdfText).not.toContain('Ø<Ýç');
    });

    it('preserves accented characters alongside emojis', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: "Politique d'Authentification",
            content: {
              type: 'doc',
              content: [
                {
                  type: 'paragraph',
                  content: [
                    {
                      type: 'text',
                      text: "🇫🇷 Résumé des règles d'authentification café",
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('handles content with only emojis', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Emoji Only',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', text: '🎉🌍😀🇬🇧' }],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
    });

    it('handles emojis in headings and list items', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: '📋 Policy Title',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'heading',
                  attrs: { level: 1 },
                  content: [{ type: 'text', text: '🔒 Security Section' }],
                },
                {
                  type: 'bulletList',
                  content: [
                    {
                      type: 'listItem',
                      content: [
                        {
                          type: 'paragraph',
                          content: [
                            { type: 'text', text: '✅ Requirement met' },
                          ],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('renders tables with header row and data cells (CS-221)', () => {
      // Regression test for CS-221: tables in policy content rendered as
      // stacked text in PDFs because there was no 'table' case in processContent.
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Data Retention Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'heading',
                  attrs: { level: 2 },
                  content: [{ type: 'text', text: 'Appendix A' }],
                },
                {
                  type: 'table',
                  content: [
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableHeader',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: 'Data Type' }],
                            },
                          ],
                        },
                        {
                          type: 'tableHeader',
                          content: [
                            {
                              type: 'paragraph',
                              content: [
                                { type: 'text', text: 'Retention Period' },
                              ],
                            },
                          ],
                        },
                      ],
                    },
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: 'User logs' }],
                            },
                          ],
                        },
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: '90 days' }],
                            },
                          ],
                        },
                      ],
                    },
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [
                                { type: 'text', text: 'Billing records' },
                              ],
                            },
                          ],
                        },
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: '7 years' }],
                            },
                          ],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
      expect(result.subarray(0, 5).toString()).toBe('%PDF-');
    });

    it('renders tables with cell colspan', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Colspan Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'table',
                  content: [
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableHeader',
                          attrs: { colspan: 2 },
                          content: [
                            {
                              type: 'paragraph',
                              content: [
                                { type: 'text', text: 'Merged header' },
                              ],
                            },
                          ],
                        },
                      ],
                    },
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: 'Left' }],
                            },
                          ],
                        },
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: 'Right' }],
                            },
                          ],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('separates text from multi-paragraph cells with newlines', () => {
      // Regression test for the CS-221 review comment: cells with multiple
      // block children (paragraphs, hardBreaks) used to be concatenated
      // without a separator, so "Retention Period" + "30 days" rendered as
      // "Retention Period30 days". extractCellText joins top-level blocks
      // with \n so splitTextToSize wraps them correctly.
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Multi-paragraph Cell Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'table',
                  content: [
                    {
                      type: 'tableRow',
                      content: [
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [
                                { type: 'text', text: 'Retention Period' },
                              ],
                            },
                            {
                              type: 'paragraph',
                              content: [{ type: 'text', text: '30 days' }],
                            },
                          ],
                        },
                        {
                          type: 'tableCell',
                          content: [
                            {
                              type: 'paragraph',
                              content: [
                                { type: 'text', text: 'Line one' },
                                { type: 'hardBreak' },
                                { type: 'text', text: 'Line two' },
                              ],
                            },
                          ],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);

      // The concatenated-without-separator strings must NOT appear in the PDF.
      const pdfText = result.toString('latin1');
      expect(pdfText).not.toContain('Retention Period30 days');
      expect(pdfText).not.toContain('Line oneLine two');
    });

    it('handles empty tables without crashing', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Empty Table Policy',
            content: {
              type: 'doc',
              content: [{ type: 'table', content: [] }],
            },
          },
        ],
        'Test Org',
      );

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBeGreaterThan(0);
    });

    it('applies custom primary color', () => {
      const result = service.renderPoliciesPdfBuffer(
        [
          {
            name: 'Branded Policy',
            content: {
              type: 'doc',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', text: 'Content' }],
                },
              ],
            },
          },
        ],
        'Branded Org',
        '#ff6600',
      );

      expect(result).toBeInstanceOf(Buffer);
    });
  });
});
