/*
 * Copyright (c) 2006, 2007 Cisco Systems.  All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX4_IB_H
#define MLX4_IB_H

#include <lego/compiler.h>
#include <lego/list.h>
#include <lego/mutex.h>

#include <rdma/ib_verbs.h>

#include <lego/mlx4/device.h>
#include <lego/mlx4/doorbell.h>

#define MLX4_IB_DRV_NAME	"mlx4_ib"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt)	"<" MLX4_IB_DRV_NAME "> %s: " fmt, __func__

enum mlx4_ib_qp_type {
	/*
	 * IB_QPT_SMI and IB_QPT_GSI have to be the first two entries
	 * here (and in that order) since the MAD layer uses them as
	 * indices into a 2-entry table.
	 */
	MLX4_IB_QPT_SMI = IB_QPT_SMI,
	MLX4_IB_QPT_GSI = IB_QPT_GSI,

	MLX4_IB_QPT_RC = IB_QPT_RC,
	MLX4_IB_QPT_UC = IB_QPT_UC,
	MLX4_IB_QPT_UD = IB_QPT_UD,
	MLX4_IB_QPT_RAW_IPV6 = IB_QPT_RAW_IPV6,
	MLX4_IB_QPT_RAW_ETHERTYPE = IB_QPT_RAW_ETHERTYPE,
	MLX4_IB_QPT_RAW_PACKET = IB_QPT_RAW_PACKET,
	MLX4_IB_QPT_XRC_INI = IB_QPT_XRC_INI,
	MLX4_IB_QPT_XRC_TGT = IB_QPT_XRC_TGT,

	MLX4_IB_QPT_PROXY_SMI_OWNER	= 1 << 16,
	MLX4_IB_QPT_PROXY_SMI		= 1 << 17,
	MLX4_IB_QPT_PROXY_GSI		= 1 << 18,
	MLX4_IB_QPT_TUN_SMI_OWNER	= 1 << 19,
	MLX4_IB_QPT_TUN_SMI		= 1 << 20,
	MLX4_IB_QPT_TUN_GSI		= 1 << 21,
};

#define MLX4_IB_QPT_ANY_SRIOV	(MLX4_IB_QPT_PROXY_SMI_OWNER | \
	MLX4_IB_QPT_PROXY_SMI | MLX4_IB_QPT_PROXY_GSI | MLX4_IB_QPT_TUN_SMI_OWNER | \
	MLX4_IB_QPT_TUN_SMI | MLX4_IB_QPT_TUN_GSI)

enum {
	MLX4_IB_SQ_MIN_WQE_SHIFT = 6,
	MLX4_IB_MAX_HEADROOM	 = 2048
};

#define MLX4_IB_SQ_HEADROOM(shift)	((MLX4_IB_MAX_HEADROOM >> (shift)) + 1)
#define MLX4_IB_SQ_MAX_SPARE		(MLX4_IB_SQ_HEADROOM(MLX4_IB_SQ_MIN_WQE_SHIFT))

enum mlx4_ib_mad_ifc_flags {
	MLX4_MAD_IFC_IGNORE_MKEY	= 1,
	MLX4_MAD_IFC_IGNORE_BKEY	= 2,
	MLX4_MAD_IFC_IGNORE_KEYS	= (MLX4_MAD_IFC_IGNORE_MKEY |
					   MLX4_MAD_IFC_IGNORE_BKEY),
	MLX4_MAD_IFC_NET_VIEW		= 4,
};

enum {
	MLX4_NUM_TUNNEL_BUFS		= 256,
};

struct mlx4_ib_tunnel_header {
	struct mlx4_av av;
	__be32 remote_qpn;
	__be32 qkey;
	__be16 vlan;
	u8 mac[6];
	__be16 pkey_index;
	u8 reserved[6];
};

struct mlx4_ib_pd {
	struct ib_pd		ibpd;
	u32			pdn;
};

struct mlx4_ib_xrcd {
	struct ib_xrcd		ibxrcd;
	u32			xrcdn;
	struct ib_pd	       *pd;
	struct ib_cq	       *cq;
};

struct mlx4_ib_cq_buf {
	struct mlx4_buf		buf;
	struct mlx4_mtt		mtt;
	int			entry_size;
};

struct mlx4_ib_cq_resize {
	struct mlx4_ib_cq_buf	buf;
	int			cqe;
};

struct mlx4_ib_cq {
	struct ib_cq		ibcq;
	struct mlx4_cq		mcq;
	struct mlx4_ib_cq_buf	buf;
	struct mlx4_ib_cq_resize *resize_buf;
	struct mlx4_db		db;
	spinlock_t		lock;
	struct mutex		resize_mutex;
};

struct mlx4_ib_mr {
	struct ib_mr		ibmr;
	struct mlx4_mr		mmr;
};

struct mlx4_ib_fast_reg_page_list {
	struct ib_fast_reg_page_list	ibfrpl;
	__be64			       *mapped_page_list;
	dma_addr_t			map;
};

struct mlx4_ib_fmr {
	struct ib_fmr           ibfmr;
	struct mlx4_fmr         mfmr;
};

struct mlx4_ib_wq {
	u64		       *wrid;
	spinlock_t		lock;
	int			wqe_cnt;
	int			max_post;
	int			max_gs;
	int			offset;
	int			wqe_shift;
	unsigned		head;
	unsigned		tail;
};

enum mlx4_ib_qp_flags {
	MLX4_IB_QP_LSO = IB_QP_CREATE_IPOIB_UD_LSO,
	MLX4_IB_QP_BLOCK_MULTICAST_LOOPBACK = IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK,
	MLX4_IB_SRIOV_TUNNEL_QP = 1 << 30,
	MLX4_IB_SRIOV_SQP = 1 << 31,
};

struct mlx4_ib_gid_entry {
	struct list_head	list;
	union ib_gid		gid;
	int			added;
	u8			port;
};

struct mlx4_ib_buf {
	void *addr;
	dma_addr_t map;
};

struct mlx4_rcv_tunnel_hdr {
	__be32 flags_src_qp; /* flags[6:5] is defined for VLANs:
			      * 0x0 - no vlan was in the packet
			      * 0x01 - C-VLAN was in the packet */
	u8 g_ml_path; /* gid bit stands for ipv6/4 header in RoCE */
	u8 reserved;
	__be16 pkey_index;
	__be16 sl_vid;
	__be16 slid_mac_47_32;
	__be32 mac_31_0;
};

struct mlx4_ib_proxy_sqp_hdr {
	struct ib_grh grh;
	struct mlx4_rcv_tunnel_hdr tun;
}  __packed;

struct mlx4_ib_qp {
	struct ib_qp		ibqp;
	struct mlx4_qp		mqp;
	struct mlx4_buf		buf;

	struct mlx4_db		db;
	struct mlx4_ib_wq	rq;

	u32			doorbell_qpn;
	__be32			sq_signal_bits;
	unsigned		sq_next_wqe;
	int			sq_max_wqes_per_wr;
	int			sq_spare_wqes;
	struct mlx4_ib_wq	sq;

	enum mlx4_ib_qp_type	mlx4_ib_qp_type;
	struct mlx4_mtt		mtt;
	int			buf_size;
	struct mutex		mutex;
	u16			xrcdn;
	u32			flags;
	u8			port;
	u8			alt_port;
	u8			atomic_rd_en;
	u8			resp_depth;
	u8			sq_no_prefetch;
	u8			state;
	int			mlx_type;
	struct list_head	gid_list;
	struct list_head	steering_rules;
	struct mlx4_ib_buf	*sqp_proxy_rcv;
};

struct mlx4_ib_srq {
	struct ib_srq		ibsrq;
	struct mlx4_srq		msrq;
	struct mlx4_buf		buf;
	struct mlx4_db		db;
	u64		       *wrid;
	spinlock_t		lock;
	int			head;
	int			tail;
	u16			wqe_ctr;
	struct mlx4_mtt		mtt;
	struct mutex		mutex;
};

struct mlx4_ib_iboe {
	spinlock_t		lock;
	union ib_gid		gid_table[MLX4_MAX_PORTS][128];
};

struct mlx4_ib_ah {
	struct ib_ah		ibah;
	union mlx4_ext_av       av;
};

struct pkey_mgt {
	u8			virt2phys_pkey[MLX4_MFUNC_MAX][MLX4_MAX_PORTS][MLX4_MAX_PORT_PKEYS];
	u16			phys_pkey_cache[MLX4_MAX_PORTS][MLX4_MAX_PORT_PKEYS];
	struct list_head	pkey_port_list[MLX4_MFUNC_MAX];
};

enum mlx4_ib_demux_pv_state {
	DEMUX_PV_STATE_DOWN,
	DEMUX_PV_STATE_STARTING,
	DEMUX_PV_STATE_ACTIVE,
	DEMUX_PV_STATE_DOWNING,
};

struct mlx4_ib_tun_tx_buf {
	struct mlx4_ib_buf buf;
	struct ib_ah *ah;
};

struct mlx4_ib_demux_pv_qp {
	struct ib_qp *qp;
	enum ib_qp_type proxy_qpt;
	struct mlx4_ib_buf *ring;
	struct mlx4_ib_tun_tx_buf *tx_ring;
	spinlock_t tx_lock;
	unsigned tx_ix_head;
	unsigned tx_ix_tail;
};

struct mlx4_ib_demux_pv_ctx {
	int port;
	int slave;
	enum mlx4_ib_demux_pv_state state;
	int has_smi;
	struct ib_device *ib_dev;
	struct ib_cq *cq;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct mlx4_ib_demux_pv_qp qp[2];
};

struct mlx4_ib_demux_ctx {
	struct ib_device *ib_dev;
	int port;
	spinlock_t ud_lock;
	__be64 subnet_prefix;
	__be64 guid_cache[128];
	struct mlx4_ib_dev *dev;
	/* the following lock protects both mcg_table and mcg_mgid0_list */
	struct mutex		mcg_table_lock;
	struct rb_root		mcg_table;
	struct list_head	mcg_mgid0_list;
	struct mlx4_ib_demux_pv_ctx **tun;
	atomic_t tid;
	int    flushing; /* flushing the work queue */
};

struct mlx4_sriov_alias_guid {
};

struct mlx4_ib_sriov {
	struct mlx4_ib_demux_ctx demux[MLX4_MAX_PORTS];
	struct mlx4_ib_demux_pv_ctx *sqps[MLX4_MAX_PORTS];
	/* when using this spinlock you should use "irq" because
	 * it may be called from interrupt context.*/
	spinlock_t going_down_lock;
	int is_going_down;

	struct mlx4_sriov_alias_guid alias_guid;

	/* CM paravirtualization fields */
	struct list_head cm_list;
	spinlock_t id_map_lock;
	struct rb_root sl_id_map;
};

struct mlx4_ib_dev {
	struct ib_device	ib_dev;
	struct mlx4_dev	       *dev;
	int			num_ports;
	void __iomem	       *uar_map;

	struct mlx4_uar		priv_uar;
	u32			priv_pdn;
	MLX4_DECLARE_DOORBELL_LOCK(uar_lock);

	struct ib_mad_agent    *send_agent[MLX4_MAX_PORTS][2];
	struct ib_ah	       *sm_ah[MLX4_MAX_PORTS];
	spinlock_t		sm_lock;
	struct mlx4_ib_sriov	sriov;

	struct mutex		cap_mask_mutex;
	bool			ib_active;
	struct mlx4_ib_iboe	iboe;
	int			counters[MLX4_MAX_PORTS];
	int		       *eq_table;
	int			eq_added;
	struct pkey_mgt		pkeys;
};

struct mlx4_ib_qp_tunnel_init_attr {
	struct ib_qp_init_attr init_attr;
	int slave;
	enum ib_qp_type proxy_qp_type;
	u8 port;
};

static inline struct mlx4_ib_dev *to_mdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct mlx4_ib_dev, ib_dev);
}

static inline struct mlx4_ib_pd *to_mpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct mlx4_ib_pd, ibpd);
}

static inline struct mlx4_ib_xrcd *to_mxrcd(struct ib_xrcd *ibxrcd)
{
	return container_of(ibxrcd, struct mlx4_ib_xrcd, ibxrcd);
}

static inline struct mlx4_ib_cq *to_mcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct mlx4_ib_cq, ibcq);
}

static inline struct mlx4_ib_cq *to_mibcq(struct mlx4_cq *mcq)
{
	return container_of(mcq, struct mlx4_ib_cq, mcq);
}

static inline struct mlx4_ib_mr *to_mmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct mlx4_ib_mr, ibmr);
}

static inline struct mlx4_ib_fast_reg_page_list *to_mfrpl(struct ib_fast_reg_page_list *ibfrpl)
{
	return container_of(ibfrpl, struct mlx4_ib_fast_reg_page_list, ibfrpl);
}

static inline struct mlx4_ib_fmr *to_mfmr(struct ib_fmr *ibfmr)
{
	return container_of(ibfmr, struct mlx4_ib_fmr, ibfmr);
}

static inline struct mlx4_ib_qp *to_mqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct mlx4_ib_qp, ibqp);
}

static inline struct mlx4_ib_qp *to_mibqp(struct mlx4_qp *mqp)
{
	return container_of(mqp, struct mlx4_ib_qp, mqp);
}

static inline struct mlx4_ib_srq *to_msrq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct mlx4_ib_srq, ibsrq);
}

static inline struct mlx4_ib_srq *to_mibsrq(struct mlx4_srq *msrq)
{
	return container_of(msrq, struct mlx4_ib_srq, msrq);
}

static inline struct mlx4_ib_ah *to_mah(struct ib_ah *ibah)
{
	return container_of(ibah, struct mlx4_ib_ah, ibah);
}

struct ib_mr *mlx4_ib_get_dma_mr(struct ib_pd *pd, int acc);
int mlx4_ib_dereg_mr(struct ib_mr *mr);
struct ib_mr *mlx4_ib_alloc_fast_reg_mr(struct ib_pd *pd,
					int max_page_list_len);
struct ib_fast_reg_page_list *mlx4_ib_alloc_fast_reg_page_list(struct ib_device *ibdev,
							       int page_list_len);
void mlx4_ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list);

int mlx4_ib_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period);
int mlx4_ib_resize_cq(struct ib_cq *ibcq, int entries);
struct ib_cq *mlx4_ib_create_cq(struct ib_device *ibdev, int entries, int vector);
int mlx4_ib_destroy_cq(struct ib_cq *cq);
int mlx4_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int mlx4_ib_arm_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags);
void __mlx4_ib_cq_clean(struct mlx4_ib_cq *cq, u32 qpn);
void mlx4_ib_cq_clean(struct mlx4_ib_cq *cq, u32 qpn);

struct ib_ah *mlx4_ib_create_ah(struct ib_pd *pd, struct ib_ah_attr *ah_attr);
int mlx4_ib_query_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr);
int mlx4_ib_destroy_ah(struct ib_ah *ah);

struct ib_srq *mlx4_ib_create_srq(struct ib_pd *pd,
				  struct ib_srq_init_attr *init_attr,
				  struct ib_udata *udata);
int mlx4_ib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
		       enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);
int mlx4_ib_query_srq(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
int mlx4_ib_destroy_srq(struct ib_srq *srq);
void mlx4_ib_free_srq_wqe(struct mlx4_ib_srq *srq, int wqe_index);
int mlx4_ib_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *wr,
			  struct ib_recv_wr **bad_wr);

struct ib_qp *mlx4_ib_create_qp(struct ib_pd *pd,
				struct ib_qp_init_attr *init_attr);
int mlx4_ib_destroy_qp(struct ib_qp *qp);
int mlx4_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask);
int mlx4_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		     struct ib_qp_init_attr *qp_init_attr);
int mlx4_ib_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		      struct ib_send_wr **bad_wr);
int mlx4_ib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr);

int mlx4_MAD_IFC(struct mlx4_ib_dev *dev, int mad_ifc_flags,
		 int port, struct ib_wc *in_wc, struct ib_grh *in_grh,
		 void *in_mad, void *response_mad);
int mlx4_ib_process_mad(struct ib_device *ibdev, int mad_flags,	u8 port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad);
int mlx4_ib_mad_init(struct mlx4_ib_dev *dev);
void mlx4_ib_mad_cleanup(struct mlx4_ib_dev *dev);

#if 0
struct ib_fmr *mlx4_ib_fmr_alloc(struct ib_pd *pd, int mr_access_flags,
				  struct ib_fmr_attr *fmr_attr);
int mlx4_ib_map_phys_fmr(struct ib_fmr *ibfmr, u64 *page_list, int npages,
			 u64 iova);
int mlx4_ib_unmap_fmr(struct list_head *fmr_list);
int mlx4_ib_fmr_dealloc(struct ib_fmr *fmr);

int mlx4_ib_resolve_grh(struct mlx4_ib_dev *dev, const struct ib_ah_attr *ah_attr,
			u8 *mac, int *is_mcast, u8 port);
#endif

static inline bool mlx4_ib_ah_grh_present(struct mlx4_ib_ah *ah)
{
	u8 port = be32_to_cpu(ah->av.ib.port_pd) >> 24 & 3;

	if (rdma_port_get_link_layer(ah->ibah.device, port) == IB_LINK_LAYER_ETHERNET)
		return true;

	return !!(ah->av.ib.g_slid & 0x80);
}

int mlx4_ib_add_mc(struct mlx4_ib_dev *mdev, struct mlx4_ib_qp *mqp,
		   union ib_gid *gid);
#endif /* MLX4_IB_H */
