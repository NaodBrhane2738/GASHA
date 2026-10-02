import { http, HttpResponse } from 'msw';
import { twinFixture } from './fixtures/twin';
import { pathsFixture } from './fixtures/paths';
import { detectionsFixture } from './fixtures/detections';
import { incidentsFixture } from './fixtures/incidents';
import { storyFixture } from './fixtures/story';
import { riskFixture } from './fixtures/risk';
import { responsesFixture } from './fixtures/responses';

let responsesState = [...responsesFixture];

export const handlers = [
  http.get('/api/twin', () => HttpResponse.json(twinFixture)),
  http.get('/api/attack-paths', () => HttpResponse.json(pathsFixture)),
  http.get('/api/detections', () => HttpResponse.json(detectionsFixture)),
  http.get('/api/detections/stream', () => {
    const pool = detectionsFixture;
    const random = pool[Math.floor(Math.random() * pool.length)];
    return HttpResponse.json({ ...random, id: `det-${Math.random().toString(36).slice(2, 8)}` });
  }),
  http.get('/api/incidents', () => HttpResponse.json(incidentsFixture)),
  http.get('/api/incidents/:id', ({ params }) => {
    const inc = incidentsFixture.find((i) => i.id === params.id);
    if (!inc) return new HttpResponse('Not found', { status: 404 });
    return HttpResponse.json(inc);
  }),
  http.get('/api/incidents/:id/story', ({ params }) => {
    const story = storyFixture[params.id as string] ?? [];
    return HttpResponse.json(story);
  }),
  http.get('/api/responses', () => HttpResponse.json(responsesState)),
  http.post('/api/responses/:id/approve', ({ params }) => {
    responsesState = responsesState.map((r) =>
      r.id === params.id ? { ...r, state: 'done' as const } : r,
    );
    const updated = responsesState.find((r) => r.id === params.id);
    return HttpResponse.json(updated);
  }),
  http.post('/api/responses/:id/reject', ({ params }) => {
    responsesState = responsesState.map((r) =>
      r.id === params.id ? { ...r, state: 'rejected' as const } : r,
    );
    const updated = responsesState.find((r) => r.id === params.id);
    return HttpResponse.json(updated);
  }),
  http.get('/api/risk', () => HttpResponse.json(riskFixture)),
];