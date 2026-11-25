/**
 * Touchque Device Risk for the browser: recognise the browser on a sign-in,
 * sign-up or payment page and tell what kind of client it is. The script tag
 * (touchque-device.global.js, served at cdn.touchque.com/device/vX.Y.Z/script.js)
 * and the same functions as a library. Reports are signed by this browser's
 * device-bound key and encrypted so only Touchque reads them.
 */
export {
  deviceRisk, createDeviceRisk, buildDeviceRiskReport, DEVICE_RISK_FIELD, DEVICE_RISK_HEADER, DEVICE_RISK_PURPOSES, consistencyFindings, jsEngine,
  LATE_EVIDENCE_CODES,
} from './deviceRisk';
export { pageMarks, onPageMarks } from './agentMarks';
export type {
  DeviceRisk, DeviceRiskPurpose, DeviceRiskReport, DeviceRiskBody, DeviceRiskTraits, DeviceRiskFindings, DeviceRiskCollectOptions,
  DeviceRiskIdentifyOptions, DeviceRiskIdentification,
} from './deviceRisk';
export { installDeviceRiskTag, REQUEST_ID_FIELD, FORM_PURPOSE_ATTRIBUTE, DEVICE_EVENT, DEVICE_TAG_VERSION } from './deviceRiskTag';
export type { DeviceRiskTagOptions, TouchqueDevice } from './deviceRiskTag';
export { startPointerSummary, encodePointerSummary } from './pointerSummary';
export type { PointerSummary, PointerSummaryProbe } from './pointerSummary';
export { startInputSummary, encodeInputSummary } from './inputSummary';
export type { InputSummary, InputSummaryProbe } from './inputSummary';
export { sealReport } from './envelope';
export { REPORT_KEY } from './reportKey';
export type { ReportKey } from './reportKey';
export { setTouchqueLogger } from './log';
export type { TouchqueWebLogger } from './log';
