# This file only contains code written by me.

# theoretical mimum for 95% of messages to have 6 bits zeroed
min_requests = 1_780
max_requests = 20_000
i = 0;
msgs = []

for _ in range(min_requests):
    json_send({ "command": "get_signature" })
    chall = json_recv()
    i += 1
    heappush(msgs, (chall["time"], chall["msg"]))

while i < max_requests:
    items = nsmallest(20, msgs)
    items = list(map(lambda x: x[1], items))
    json_send({ "command": "solve", "messages": items })
    ans = json_recv()
    if "flag" in ans:
        print(i)
        print(ans["flag"])
        break

    # Let's get 20 more messages so hopefully we find ones with more zero bits
    for _ in range(20):
        json_send({ "command": "get_signature" })
        chall = json_recv()
        i += 1
        heappush(msgs, (chall["time"], chall["msg"]))
