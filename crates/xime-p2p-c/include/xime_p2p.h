/* xime-p2p C ABI —— 供非 Rust 宿主（鸿蒙 NAPI）调用。
 *
 * 约定：
 *   - 所有入参是 UTF-8 C 字符串；所有返回是 JSON 字符串，形如
 *     {"ok":true,...} 或 {"ok":false,"error":"..."}。
 *   - 返回的字符串必须用 xime_p2p_free() 释放，不要 free()。
 *   - 单进程内 Node 与配对任务各只有一个，调用需串行。
 */
#ifndef XIME_P2P_H
#define XIME_P2P_H

#ifdef __cplusplus
extern "C" {
#endif

/* 加载或生成本机身份：-> {ok,did} */
char *xime_p2p_identity(const char *dir);

/* 启动同步节点：-> {ok,did,port} */
char *xime_p2p_start(const char *dir, int listen, int discover, int port);

/* 关闭同步节点。返回 1 表示原本在运行。 */
int xime_p2p_stop(void);

/* 投递一条文本剪贴板条目。返回 1 表示已入队。 */
int xime_p2p_set_clipboard(const char *text, const char *source);

/* 取事件（非阻塞）：-> {ok,events:[{type:"clipboard"|"peer"|"warning",...}]} */
char *xime_p2p_poll(int max);

/* 节点状态：-> {ok,running,did,port} */
char *xime_p2p_status(void);

/* 显示端配对：-> {ok,code,port} */
char *xime_p2p_pair_display(const char *dir, const char *name, int timeout_sec);

/* 输入端配对（addr 可传 NULL 走局域网发现）：-> {ok} */
char *xime_p2p_pair_input(const char *dir, const char *name, const char *code,
                          const char *addr, int timeout_sec);

/* 配对进度：-> {ok,phase,code,port,peer,error} */
char *xime_p2p_pair_poll(void);

/* 取消配对。返回 1 表示确实取消了。 */
int xime_p2p_pair_cancel(void);

/* 已配对设备：-> {ok,peers:[{did,name,last_addr,paired_at}]} */
char *xime_p2p_peers(const char *dir);

/* 删除已配对设备。返回 1 表示确实删掉了。 */
int xime_p2p_forget(const char *dir, const char *did);

/* 释放本库返回的字符串。 */
void xime_p2p_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* XIME_P2P_H */
