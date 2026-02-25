# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest.mock import AsyncMock

import pytest

from forge.sandbox.models import SandboxSnapshot
from forge.tools.observation import GetAppLogs


def _session() -> AsyncMock:
    s = AsyncMock()
    s.snapshot = AsyncMock()
    s.read_file = AsyncMock()
    return s


class TestObservationTools:
    @pytest.mark.asyncio
    async def test_get_app_logs(self) -> None:
        s = _session()
        s.snapshot.return_value = SandboxSnapshot(
            app_logs="INFO: ok\nERROR: crash\nINFO: more",
        )
        r = await GetAppLogs(s).execute({"filter": "ERROR"})
        assert "crash" in r.content
        assert "ok" not in r.content
