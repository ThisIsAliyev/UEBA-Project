"""
Async queue for non-blocking AI analysis.

Events are queued and processed in background workers, ensuring the main
event ingest pipeline is never blocked by slow AI analysis.

Architecture:
1. Event arrives → Rule scoring → Store with preliminary score
2. If AI needed → Queue for async analysis
3. Background worker → Call AI Server → Update event score
4. If score crosses alert threshold → Create/update alert
"""

import asyncio
import logging
import time
import uuid
from typing import Optional, Callable, Awaitable, Dict, Any
from dataclasses import dataclass, field

from .client import get_ai_client
from .models import EnrichmentRequest, EnrichmentResponse

logger = logging.getLogger(__name__)


@dataclass
class QueuedAnalysis:
    """Item in the analysis queue."""
    request: EnrichmentRequest
    event_id: int  # Database event ID for updating
    queued_at: float = field(default_factory=time.time)
    callback: Optional[Callable[[EnrichmentResponse, int], Awaitable[None]]] = None


class AIAnalysisQueue:
    """
    Async queue for non-blocking AI analysis.
    
    Features:
    - Configurable queue size with overflow protection
    - Multiple background workers for parallel processing
    - Stale request detection (skip old requests)
    - Callback support for result handling
    
    Usage:
        queue = AIAnalysisQueue()
        await queue.start()
        
        # Queue an analysis
        await queue.enqueue(request, event_id, callback=handle_result)
        
        # Shutdown
        await queue.stop()
    """
    
    def __init__(
        self,
        max_size: int = 100,
        num_workers: int = 2,
        max_age_seconds: float = 120.0
    ):
        """
        Initialize analysis queue.
        
        Args:
            max_size: Maximum queue size (overflow drops oldest)
            num_workers: Number of background workers
            max_age_seconds: Skip requests older than this
        """
        self.max_size = max_size
        self.num_workers = num_workers
        self.max_age_seconds = max_age_seconds
        
        self._queue: asyncio.Queue[QueuedAnalysis] = asyncio.Queue(maxsize=max_size)
        self._workers: list[asyncio.Task] = []
        self._running = False
        
        # Statistics
        self._stats = {
            "queued": 0,
            "processed": 0,
            "dropped": 0,
            "stale": 0,
            "errors": 0,
        }
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get queue statistics."""
        return {
            **self._stats,
            "pending": self._queue.qsize(),
            "workers": len(self._workers),
        }
    
    async def start(self):
        """Start background workers."""
        if self._running:
            return
        
        self._running = True
        for i in range(self.num_workers):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)
        
        logger.info(f"AI analysis queue started with {self.num_workers} workers")
    
    async def stop(self):
        """Stop background workers gracefully."""
        self._running = False
        
        # Cancel all workers
        for task in self._workers:
            task.cancel()
        
        # Wait for workers to finish
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        
        self._workers.clear()
        logger.info("AI analysis queue stopped")
    
    async def enqueue(
        self,
        request: EnrichmentRequest,
        event_id: int,
        callback: Optional[Callable[[EnrichmentResponse, int], Awaitable[None]]] = None
    ) -> bool:
        """
        Add analysis request to queue.
        
        Args:
            request: EnrichmentRequest with event data
            event_id: Database event ID for updating results
            callback: Optional async function called with (response, event_id)
            
        Returns:
            True if queued successfully, False if queue is full
        """
        item = QueuedAnalysis(
            request=request,
            event_id=event_id,
            callback=callback
        )
        
        try:
            self._queue.put_nowait(item)
            self._stats["queued"] += 1
            logger.debug(f"Queued AI analysis for event {event_id}")
            return True
            
        except asyncio.QueueFull:
            self._stats["dropped"] += 1
            logger.warning(
                f"AI analysis queue full ({self.max_size}), "
                f"dropping request for event {event_id}"
            )
            return False
    
    async def _worker(self, worker_id: int):
        """
        Background worker that processes queued analysis requests.
        
        Args:
            worker_id: Worker identifier for logging
        """
        client = get_ai_client()
        logger.debug(f"AI analysis worker {worker_id} started")
        
        while self._running:
            try:
                # Wait for item with timeout (allows checking _running flag)
                try:
                    item = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Check if request is too old
                age = time.time() - item.queued_at
                if age > self.max_age_seconds:
                    self._stats["stale"] += 1
                    logger.debug(
                        f"Skipping stale AI request for event {item.event_id} "
                        f"(age: {age:.1f}s)"
                    )
                    self._queue.task_done()
                    continue
                
                # Process the request
                try:
                    logger.debug(
                        f"Worker {worker_id} processing event {item.event_id}"
                    )
                    
                    response = await client.analyze(item.request)
                    self._stats["processed"] += 1
                    
                    # Call callback if provided
                    if item.callback:
                        await item.callback(response, item.event_id)
                    
                    logger.debug(
                        f"AI analysis complete for event {item.event_id}: "
                        f"label={response.label}, score={response.score}"
                    )
                    
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.exception(
                        f"Worker {worker_id} error processing event {item.event_id}: {e}"
                    )
                
                finally:
                    self._queue.task_done()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Worker {worker_id} unexpected error: {e}")
        
        logger.debug(f"AI analysis worker {worker_id} stopped")


# Global queue instance
_analysis_queue: Optional[AIAnalysisQueue] = None


def get_analysis_queue() -> AIAnalysisQueue:
    """Get or create global analysis queue instance."""
    global _analysis_queue
    
    if _analysis_queue is None:
        _analysis_queue = AIAnalysisQueue()
    
    return _analysis_queue


async def start_analysis_queue():
    """Start the global analysis queue."""
    queue = get_analysis_queue()
    await queue.start()


async def stop_analysis_queue():
    """Stop the global analysis queue."""
    global _analysis_queue
    
    if _analysis_queue is not None:
        await _analysis_queue.stop()
        _analysis_queue = None
