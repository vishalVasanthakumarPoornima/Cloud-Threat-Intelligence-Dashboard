from collections import OrderedDict
from threading import Lock
from uuid import UUID

from app.schemas.results import AnalysisResponse

MAX_STORED_RESULTS = 100

_results: OrderedDict[str, AnalysisResponse] = OrderedDict()
_lock = Lock()


def save_result(result: AnalysisResponse) -> None:
    key = str(result.analysis_id)
    with _lock:
        _results[key] = result
        _results.move_to_end(key)
        while len(_results) > MAX_STORED_RESULTS:
            _results.popitem(last=False)


def get_result(analysis_id: UUID) -> AnalysisResponse | None:
    key = str(analysis_id)
    with _lock:
        result = _results.get(key)
        if result:
            _results.move_to_end(key)
        return result
