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

class GenerationFailedError(Exception):
    """Raised when app generation fails after all retry attempts."""

    def __init__(self, cve_id: str, attempts: int, last_error: str) -> None:
        self.cve_id = cve_id
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(f"Generation failed for {cve_id} after {attempts} attempts: {last_error}")
