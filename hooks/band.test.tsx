import { expect, test } from 'claude-code/testing'

const BAND = {
  component: 'AbovePrompt',
  props: { hasSurvey: false, isWorking: true, maxRows: 10, bodyColumns: 80, scroll: { offset: 0, bodyRows: 10 }, view: {} },
} as const

test('the desktop app gets a button that opens the pane mid-turn; the terminal does not', async ($, on) => {
  // the engine's own band: nothing
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => { const { Box } = $.ui.resolve(e); return <Box /> })
  const desktop = await $.ui.mount({ plugin: 'vault', surface: 'desktop', ...BAND })
  expect((await desktop.find({ key: 'vault-open' }))?.text).toContain('Vault')
  await desktop.unmount()
  const terminal = await $.ui.mount({ plugin: 'vault', surface: 'terminal', ...BAND })
  expect(await terminal.find({ key: 'vault-open' })).toBeUndefined()
  await terminal.unmount()
  const survey = await $.ui.mount({ plugin: 'vault', surface: 'desktop', ...BAND, props: { ...BAND.props, hasSurvey: true } })
  expect(await survey.find({ key: 'vault-open' })).toBeUndefined()
  await survey.unmount()
})
