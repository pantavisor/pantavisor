/*
 * PVCM Shell Demo
 *
 * Demonstrates the Pantavisor MCU SDK: heartbeat, shell, and HTTP API.
 * Tests concurrent HTTP requests: a slow upload in a background thread
 * while GET requests run in the main thread.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_demo, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_PANTAVISOR_BRIDGE

static void on_response(uint16_t status, const char *body,
			size_t body_len, const char *headers, void *ctx)
{
	const char *label = ctx ? (const char *)ctx : "HTTP";
	LOG_INF("%s: status=%d body_len=%zu", label, status, body_len);
	if (body_len > 0 && body_len <= 200)
		LOG_INF("  body: %.*s", (int)body_len, body);
}

/* Background thread: does a slow 2KB upload */
#define UPLOAD_STACK_SIZE 4096
#define UPLOAD_PRIORITY   10
static K_THREAD_STACK_DEFINE(upload_stack, UPLOAD_STACK_SIZE);
static struct k_thread upload_thread;
static volatile bool upload_done = false;

static void upload_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

	LOG_INF("[upload] starting 2KB PUT to /api/upload/test.bin");

	static char big_body[2048];
	for (int i = 0; i < sizeof(big_body); i++)
		big_body[i] = 'A' + (i % 26);

	int ret = pvcm_put("/api/upload/test.bin", big_body,
			   sizeof(big_body), on_response, "UPLOAD");
	LOG_INF("[upload] done: ret=%d", ret);
	upload_done = true;
}

static void run_http_tests(void)
{
	int ret;

	LOG_INF("=== Sequential HTTP Tests ===");

	LOG_INF("Test 1: GET /api/status");
	ret = pvcm_get("/api/status", on_response, "GET-status");
	LOG_INF("  result: %d", ret);

	LOG_INF("Test 2: GET /api/config");
	ret = pvcm_get("/api/config", on_response, "GET-config");
	LOG_INF("  result: %d", ret);

	LOG_INF("Test 3: POST /api/data");
	const char *post_body = "{\"sensor\":\"temp\",\"value\":22.4}";
	ret = pvcm_post("/api/data", post_body, strlen(post_body),
			on_response, "POST-data");
	LOG_INF("  result: %d", ret);

	LOG_INF("Test 4: DELETE /api/data/1");
	ret = pvcm_delete("/api/data/1", on_response, "DELETE");
	LOG_INF("  result: %d", ret);

	LOG_INF("=== Sequential Tests Done ===");

	/* Test 5: Concurrent upload + GET
	 * Start slow upload in background, then do GETs while it runs */
	LOG_INF("=== Concurrent Test: Upload + GET ===");

	k_thread_create(&upload_thread, upload_stack,
			K_THREAD_STACK_SIZEOF(upload_stack),
			upload_thread_fn, NULL, NULL, NULL,
			UPLOAD_PRIORITY, 0, K_NO_WAIT);

	/* give upload thread time to start and send HTTP_REQ */
	k_sleep(K_MSEC(500));

	/* now do GETs while upload is blocked on server response */
	LOG_INF("[main] doing GETs while upload is in progress...");
	for (int i = 0; i < 3 && !upload_done; i++) {
		LOG_INF("[main] GET /api/status (#%d)", i + 1);
		ret = pvcm_get("/api/status", on_response, "GET-concurrent");
		LOG_INF("[main]   result: %d, upload_done=%d", ret,
			upload_done);
		k_sleep(K_SECONDS(1));
	}

	/* wait for upload to finish */
	k_thread_join(&upload_thread, K_SECONDS(15));
	LOG_INF("=== Concurrent Test Done ===");

	/* Verify link still works after concurrent test */
	LOG_INF("Test 6: GET /api/status (final)");
	ret = pvcm_get("/api/status", on_response, "GET-final");
	LOG_INF("  result: %d", ret);

	LOG_INF("=== All Tests Complete ===");
}

#endif /* CONFIG_PANTAVISOR_BRIDGE */

int main(void)
{
	LOG_INF("PVCM shell demo starting");

#ifdef CONFIG_PANTAVISOR_BRIDGE
	LOG_INF("Waiting 8s for pvcm-proxy connection...");
	k_sleep(K_SECONDS(8));
	run_http_tests();
#endif

	return 0;
}
