import { LoaderCircle } from "lucide-react"
import { useState, useSyncExternalStore } from "react"

import { Card } from "../../components/ui/Card"
import { Disclosure, DisclosureGroup } from "../../components/ui/Disclosure"
import { Pane } from "../../components/ui/Pane"
import { PushButton } from "../../components/ui/PushButton"
import { SegmentedControl } from "../../components/ui/SegmentedControl"
import { SectionGroup } from "../../components/ui/SectionGroup"
import { StatusText } from "../../components/ui/StatusText"
import { ToggleSwitch } from "../../components/ui/ToggleSwitch"
import {
  emptyCheckAvailability,
  getCheckAvailability,
  onCheckAvailabilityChanged,
  removeTypeSafeApiKey,
  runCheckBackfill,
  setCheckHistoryDays,
  setTypeSafeApiKey,
  setSmartBurnChecksEnabled,
  type CheckAvailability,
} from "../../lib/checkAvailability"
import { SettingsRow } from "./SettingsSearchRows"

const initial = emptyCheckAvailability
let snapshot = initial
const listeners = new Set<() => void>()
let stop: (() => void) | undefined
let revision = 0

function publish(value: CheckAvailability) {
  revision++
  snapshot = value
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  if (listeners.size === 1) {
    const current = ++revision
    void onCheckAvailabilityChanged(publish)
      .then((unsubscribe) => {
        if (listeners.size) stop = unsubscribe
        else unsubscribe()
        if (!listeners.size) return
        const request = revision
        void getCheckAvailability()
          .then((value) => {
            if (revision === request) publish(value)
          })
          .catch(() => {
            if (revision === request)
              publish({ ...initial, error: "Could not load check status." })
          })
      })
      .catch(() => {
        if (revision === current) publish({ ...initial, error: "Could not load check status." })
      })
  }
  return () => {
    listeners.delete(listener)
    if (!listeners.size) {
      stop?.()
      stop = undefined
    }
  }
}

function historyStatus(state: CheckAvailability): string | null {
  const { backfill } = state
  const waiting = backfill.ready + backfill.queued
  const parts = [
    waiting > 0 ? `${waiting} waiting to be checked` : null,
    backfill.waitingForData > 0
      ? `${backfill.waitingForData} waiting for session analysis`
      : null,
    backfill.waitingForIdle > 0
      ? `${backfill.waitingForIdle} waiting for session to be idle`
      : null,
    backfill.completed > 0 ? `${backfill.completed} checked` : null,
    backfill.skipped > 0 ? `${backfill.skipped} not eligible` : null,
    backfill.failed > 0 ? `${backfill.failed} failed` : null,
  ].filter((part): part is string => part !== null)
  return parts.length > 0 ? parts.join(" · ") : null
}

export function ChecksPane() {
  const state = useSyncExternalStore(
    subscribe,
    () => snapshot,
    () => initial,
  )
  const [key, setKey] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function saveHistoryDays(days: 0 | 7 | 30) {
    setBusy(true)
    setError(null)
    try {
      publish(await setCheckHistoryDays(days))
    } catch {
      setError("Could not save the history period.")
    } finally {
      setBusy(false)
    }
  }

  async function runHistory() {
    setBusy(true)
    setError(null)
    try {
      const result = await runCheckBackfill()
      publish(result.availability)
    } catch {
      setError("Could not start checks. Check the TypeSafe API key and try again.")
    } finally {
      setBusy(false)
    }
  }

  async function save() {
    setBusy(true)
    setError(null)
    try {
      publish(await setTypeSafeApiKey(key))
      setKey("")
    } catch {
      setError("Could not save the key in secure storage.")
    } finally {
      setBusy(false)
    }
  }

  async function remove() {
    setBusy(true)
    setError(null)
    try {
      publish(await removeTypeSafeApiKey())
    } catch {
      setError("Could not remove the key from secure storage.")
    } finally {
      setBusy(false)
    }
  }

  async function toggleChecks(enabled: boolean) {
    setBusy(true)
    setError(null)
    try {
      publish(await setSmartBurnChecksEnabled(enabled))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update Smart Burn Checks.")
    } finally {
      setBusy(false)
    }
  }

  const usage =
    state.usage.inputTokens > 0 || state.usage.confirmedCalls > 0
      ? `${state.usage.inputTokens.toLocaleString()} input tokens · ${state.usage.estimatedUsd ?? "cost unavailable"} estimated · ${state.usage.confirmedCalls.toLocaleString()} requests`
      : "No TypeSafe requests yet."
  const historyValue = String(state.historyDays)
  const progress = historyStatus(state)
  const historyRunning = state.backfill.queued + state.backfill.running > 0
  const historyTotal = state.backfill.total

  return (
    <Pane title="Checks">
      <div className="space-y-6">
        <SectionGroup title="Smart Burn Checks">
          <Card>
            <SettingsRow
              searchId="ignoredInstructions"
              label="Ignored Instructions"
              description="Finds project instructions a session did not follow. Checks start after 3 minutes of inactivity."
            />
            <p className="mt-2 px-3 pb-3 pt-2 type-footnote text-label-tertiary">
              More Smart Burn Checks coming soon.
            </p>
          </Card>
        </SectionGroup>

        <SectionGroup title="Past sessions">
          <Card>
            <SettingsRow
              searchId="checkHistory"
              label="Check history"
              description="Choose a period. Checks start only when you ask."
            >
              <SegmentedControl
                ariaLabel="Check history window"
                value={historyValue}
                onChange={(value) => {
                  if (value === "0") void saveHistoryDays(0)
                  else if (value === "7") void saveHistoryDays(7)
                  else if (value === "30") void saveHistoryDays(30)
                }}
                disabled={busy}
                equalWidth
                variant="native-tabs"
                className="mt-2 w-full"
                options={[
                  { value: "0", label: "Future only" },
                  { value: "7", label: "7 days" },
                  { value: "30", label: "30 days" },
                ]}
              />
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <PushButton
                  variant="primary"
                  disabled={
                    busy || historyRunning || !state.configured || state.historyDays === 0
                  }
                  onClick={() => void runHistory()}
                >
                  Check past sessions
                </PushButton>
                <StatusText tone="secondary">TypeSafe charges may apply.</StatusText>
              </div>
              {(progress || historyRunning || state.backfill.ready > 0) && (
                <div className="mt-3 space-y-1" role="status" aria-live="polite">
                  {historyRunning && (
                    <StatusText
                      icon={LoaderCircle}
                      iconClassName="animate-spin"
                      tone="secondary"
                    >
                      Checking sessions; {state.backfill.completed.toLocaleString()}/
                      {historyTotal.toLocaleString()} sessions checked so far
                    </StatusText>
                  )}
                  {!historyRunning && progress && (
                    <p className="type-footnote text-label-secondary">{progress}</p>
                  )}
                </div>
              )}
            </SettingsRow>
          </Card>
        </SectionGroup>

        <SectionGroup title="TypeSafe account">
          <Card>
            <SettingsRow
              searchId="typeSafeApiKey"
              label="API key"
              description="Enter your TypeSafe API key to enable Smart Burn Checks. TypeSafe usage charges may apply."
            >
              <input
                id="typesafe-key"
                aria-label="TypeSafe API key"
                type="password"
                autoComplete="off"
                placeholder={state.savedKey ? "••••••••••••" : undefined}
                value={key}
                onChange={(event) => setKey(event.target.value)}
                className="mt-2 min-h-[var(--control-height-regular)] w-full rounded-control border border-separator bg-input-fill px-3 type-body text-label"
              />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {state.savedKey && (
                  <ToggleSwitch
                    aria-label="Smart Burn Checks"
                    checked={state.configured}
                    disabled={busy || Boolean(state.error)}
                    onCheckedChange={(enabled) => void toggleChecks(enabled)}
                  />
                )}
                <PushButton disabled={busy || !key.trim()} onClick={() => void save()}>
                  {state.savedKey ? "Replace key" : "Save key and enable"}
                </PushButton>
                {(state.configured || state.savedKey) && (
                  <PushButton disabled={busy} onClick={() => void remove()}>
                    Remove key
                  </PushButton>
                )}
              </div>
              {(error || state.error) && (
                <p role="alert" className="mt-2 type-footnote text-system-red-text">
                  {error || state.error}
                </p>
              )}
            </SettingsRow>
          </Card>
          <DisclosureGroup className="mt-2 px-1">
            <Disclosure label="Privacy and usage">
              <p>
                Jev compares selected project instructions with assistant text excerpts and
                complete normalized tool inputs, including shell commands and structured
                arguments. Tool-result text is removed before the request. This content is sent
                to TypeSafe using your key. API usage can cost money; local totals count
                confirmed requests and tokens.
              </p>
              <p className="mt-2">{usage}</p>
              {state.usage.unknownOutcomes > 0 && (
                <p className="mt-1">
                  {state.usage.unknownOutcomes.toLocaleString()} request outcomes are unknown
                  and are not included in the estimate.
                </p>
              )}
            </Disclosure>
          </DisclosureGroup>
        </SectionGroup>
      </div>
    </Pane>
  )
}
