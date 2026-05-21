export interface AnalyticsEvent {
  readonly anonymousId?: string;
  readonly userId?: string;
  readonly event?: string;
  readonly properties?: Record<string, unknown>;
}

export class Analytics {
  constructor(_options?: Record<string, unknown>) {}

  track(_event: AnalyticsEvent): void {}

  identify(_event: AnalyticsEvent): void {}

  group(_event: AnalyticsEvent): void {}

  page(_event: AnalyticsEvent): void {}

  screen(_event: AnalyticsEvent): void {}

  alias(_event: AnalyticsEvent): void {}

  async flush(): Promise<void> {}

  async closeAndFlush(): Promise<void> {}
}

export default Analytics;
