import { createTracker } from '@bakery/analytics';

const tracker = globalThis.__bakeryTracker || (globalThis.__bakeryTracker = createTracker({ site: 'bakery-shop' }));
export const track = (event, props) => tracker.track(event, props);
export const stats = () => tracker.stats();
