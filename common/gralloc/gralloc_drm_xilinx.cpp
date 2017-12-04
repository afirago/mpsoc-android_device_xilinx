#include <cutils/log.h>
#include <stdlib.h>
#include <errno.h>
#include <drm.h>

#include <xf86drm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "gralloc_priv.h"

#define UNUSED(...) (void)(__VA_ARGS__)

struct xilinx_device {
	int fd;
};

/*
 * Buffer Object structure.
 *
 * @dev: xilinx device object allocated.
 * @handle: a gem handle to gem object created.
 * @flags: indicate memory allocation and cache attribute types.
 * @size: size to the buffer created.
 * @vaddr: user space address to a gem buffer mmaped.
 * @name: a gem global handle from flink request.
 */
struct xilinx_bo {
	struct xilinx_device	*dev;
	uint32_t		handle;
	uint32_t		flags;
	size_t			size;
	void			*vaddr;
	uint32_t		name;
};

struct xilinx_info {
	struct gralloc_drm_drv_t base;

	struct xilinx_device *xilinx;
	int fd;
};

struct xilinx_buffer {
	struct gralloc_drm_bo_t base;

	struct xilinx_bo *bo;
};

/**
 * User-desired buffer creation information structure.
 *
 * @size: user-desired memory allocation size.
 *	- this size value would be page-aligned internally.
 * @flags: user request for setting memory type or cache attributes.
 * @handle: returned a handle to created gem object.
 *	- this handle will be set by gem module of kernel side.
 */
struct drm_xilinx_gem_create {
	uint64_t size;
	uint32_t flags;
	uint32_t handle;
};

/**
 * A structure for getting buffer offset.
 *
 * @handle: a pointer to gem object created.
 * @pad: just padding to be 64-bit aligned.
 * @offset: relatived offset value of the memory region allocated.
 *	- this value should be set by user.
 */
struct drm_xilinx_gem_map_off {
	uint32_t handle;
	uint32_t pad;
	uint64_t offset;
};

/*
 * Create xilinx drm device object.
 *
 * @fd: file descriptor to xilinx drm driver opened.
 *
 * if true, return the device object else NULL.
 */
struct xilinx_device *xilinx_device_create(int fd)
{
	struct xilinx_device *dev;

	dev = (struct xilinx_device *)calloc(1, sizeof(*dev));
	if (!dev) {
		fprintf(stderr, "failed to create device[%s].\n",
				strerror(errno));
		return NULL;
	}

	dev->fd = fd;

	return dev;
}

/*
 * Destroy xilinx drm device object
 *
 * @dev: xilinx drm device object.
 */
void xilinx_device_destroy(struct xilinx_device *dev)
{
	free(dev);
}

/*
 * Create a xilinx buffer object to xilinx drm device.
 *
 * @dev: xilinx drm device object.
 * @size: user-desired size.
 * flags: user-desired memory type.
 *	user can set one or more types among several types to memory
 *	allocation and cache attribute types. and as default,
 *	XILINX_BO_NONCONTIG and XILINX-BO_NONCACHABLE types would
 *	be used.
 *
 * if true, return a xilinx buffer object else NULL.
 */
struct xilinx_bo *xilinx_bo_create(struct xilinx_device *dev,
	int width, int height, int bpp, uint32_t flags)
{
	struct xilinx_bo *bo;
	struct drm_mode_create_dumb gem;
	int ret;

	/*
		TODO: implement args sanity checking
	*/ 

	bo = (struct xilinx_bo *)calloc(1, sizeof(*bo));
	if (!bo) {
		fprintf(stderr, "failed to create bo[%s].\n",
				strerror(errno));
		goto fail;
	}

	bo->dev = dev;

	memset(&gem, 0, sizeof gem);
	gem.width = width;
	gem.height = height;
	gem.bpp = bpp;

	/*
	 * Creates a gem object.
	 * The kernel will return a 32bit handle that can be used to
	 * manage the buffer with the DRM API
	 */
	ret = ioctl(dev->fd, DRM_IOCTL_MODE_CREATE_DUMB, &gem);
	if (ret) {
		fprintf(stderr, "failed to create gem object[%s].\n",
				strerror(errno));
		goto err_free_bo;
	}

	bo->handle = gem.handle;
	bo->size = gem.size;
	bo->flags = flags;

	return bo;

err_free_bo:
	free(bo);
fail:
	return NULL;
}

struct xilinx_bo *xilinx_bo_from_handle(struct xilinx_device *dev,
			uint32_t handle, uint32_t flags, uint32_t size)
{
	struct xilinx_bo *bo;

	if (size == 0) {
		fprintf(stderr, "invalid size.\n");
		return NULL;
	}

	bo = (struct xilinx_bo *)calloc(1, sizeof(*bo));
	if (!bo) {
		fprintf(stderr, "failed to create bo[%s].\n",
				strerror(errno));
		return NULL;
	}

	bo->dev = dev;
	bo->handle = handle;
	bo->size = size;
	bo->flags = flags;

	return bo;
}

/*
 * Destroy a xilinx buffer object.
 *
 * @bo: a xilinx buffer object to be destroyed.
 */
void xilinx_bo_destroy(struct xilinx_bo *bo)
{
	if (!bo)
		return;

	if (bo->vaddr)
		munmap(bo->vaddr, bo->size);

	if (bo->handle) {
		struct drm_gem_close req = {
			.handle = bo->handle,
		};

		drmIoctl(bo->dev->fd, DRM_IOCTL_GEM_CLOSE, &req);
	}

	free(bo);
}


/*
 * Get a xilinx buffer object from a gem global object name.
 *
 * @dev: a xilinx device object.
 * @name: a gem global object name exported by another process.
 *
 * this interface is used to get a xilinx buffer object from a gem
 * global object name sent by another process for buffer sharing.
 *
 * if true, return a xilinx buffer object else NULL.
 *
 */
struct xilinx_bo *xilinx_bo_from_name(struct xilinx_device *dev,
						uint32_t name)
{
	struct xilinx_bo *bo;
	struct drm_gem_open req = {
		.name = name,
	};

	bo = (struct xilinx_bo *)calloc(1, sizeof(*bo));
	if (!bo) {
		fprintf(stderr, "failed to allocate bo[%s].\n",
				strerror(errno));
		return NULL;
	}

	if (drmIoctl(dev->fd, DRM_IOCTL_GEM_OPEN, &req)) {
		fprintf(stderr, "failed to open gem object[%s].\n",
				strerror(errno));
		goto err_free_bo;
	}

	bo->dev = dev;
	bo->name = name;
	bo->handle = req.handle;

	return bo;

err_free_bo:
	free(bo);
	return NULL;
}

/*
 * Get a gem global object name from a gem object handle.
 *
 * @bo: a xilinx buffer object including gem handle.
 * @name: a gem global object name to be got by kernel driver.
 *
 * this interface is used to get a gem global object name from a gem object
 * handle to a buffer that wants to share it with another process.
 *
 * if true, return 0 else negative.
 */
int xilinx_bo_get_name(struct xilinx_bo *bo, uint32_t *name)
{
	if (!bo->name) {
		struct drm_gem_flink req = {
			.handle = bo->handle,
		};
		int ret;

		ret = drmIoctl(bo->dev->fd, DRM_IOCTL_GEM_FLINK, &req);
		if (ret) {
			fprintf(stderr, "failed to get gem global name[%s].\n",
					strerror(errno));
			return ret;
		}

		bo->name = req.name;
	}

	*name = bo->name;

	return 0;
}

uint32_t xilinx_bo_handle(struct xilinx_bo *bo)
{
	return bo->handle;
}

/*
 * Mmap a buffer to user space.
 *
 * @bo: a xilinx buffer object including a gem object handle to be mmapped
 *	to user space.
 *
 * if true, user pointer mmaped else NULL.
 */
void *xilinx_bo_map(struct xilinx_bo *bo)
{
	if (!bo->vaddr) {
		struct xilinx_device *dev = bo->dev;
		struct drm_mode_map_dumb mreq;
		int ret;

		memset(&mreq, 0, sizeof(mreq));
		mreq.handle = bo->handle;

		ret = drmIoctl(dev->fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq);
		if (ret) {
			fprintf(stderr, "cannot map dumb buffer[%s].\n",
				strerror(errno));
			return NULL;
		}

		bo->vaddr = mmap(0, bo->size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, dev->fd, mreq.offset);
		if (bo->vaddr == MAP_FAILED) {
			fprintf(stderr, "failed to mmap buffer[%s].\n",
				strerror(errno));
			return NULL;
		}
	}

	return bo->vaddr;
}


static void drm_gem_xilinx_destroy(struct gralloc_drm_drv_t *drv)
{
#if 1
	struct xilinx_info *info = (struct xilinx_info *)drv;

	if (info->xilinx)
		xilinx_device_destroy(info->xilinx);
	free(info);
#endif
}

static struct gralloc_drm_bo_t *drm_gem_xilinx_alloc(
		struct gralloc_drm_drv_t *drv,
		struct private_handle_t *handle)
{
#if 0
	struct xilinx_info *info = (struct xilinx_info *)drv;
	struct xilinx_buffer *buf;
	struct drm_gem_close args;
	int ret, cpp, pitch;
	uint32_t size, gem_handle;

	buf = calloc(1, sizeof(*buf));
	if (!buf) {
		ALOGE("Failed to allocate buffer wrapper\n");
		return NULL;
	}

	cpp = gralloc_drm_get_bpp(handle->format);
	if (!cpp) {
		ALOGE("unrecognized format 0x%x", handle->format);
		return NULL;
	}

	gralloc_drm_align_geometry(handle->format,
			&handle->width, &handle->height);

	/* TODO: We need to sort out alignment */
	pitch = ALIGN(handle->width * cpp, 64);
	size = handle->height * pitch;

	if (handle->prime_fd >= 0) {
		ret = drmPrimeFDToHandle(info->fd, handle->prime_fd,
			&gem_handle);
		if (ret) {
			char *c = NULL;
			ALOGE("failed to convert prime fd to handle %d ret=%d",
				handle->prime_fd, ret);
			*c = 0;
			goto err;
		}
		ALOGV("Got handle %d for fd %d\n", gem_handle, handle->prime_fd);

		buf->bo = xilinx_bo_from_handle(info->xilinx, gem_handle,
			0, size);
		if (!buf->bo) {
			ALOGE("failed to wrap bo handle=%d size=%d\n",
				gem_handle, size);

			memset(&args, 0, sizeof(args));
			args.handle = gem_handle;
			drmIoctl(info->fd, DRM_IOCTL_GEM_CLOSE, &args);
			return NULL;
		}
	} else {
		buf->bo = xilinx_bo_create(info->xilinx, handle->width, handle->height, cpp, 0);
		if (!buf->bo) {
			ALOGE("failed to allocate bo %dx%dx%dx%d\n",
				handle->height, pitch, cpp, size);
			goto err;
		}

		gem_handle = xilinx_bo_handle(buf->bo);
		ret = drmPrimeHandleToFD(info->fd, gem_handle, 0,
			&handle->prime_fd);
		ALOGV("Got fd %d for handle %d\n", handle->prime_fd, gem_handle);
		if (ret) {
			ALOGE("failed to get prime fd %d", ret);
			goto err_unref;
		}

		buf->base.fb_handle = gem_handle;
	}

	handle->name = 0;
	handle->stride = pitch;
	buf->base.handle = handle;

	return &buf->base;

err_unref:
	xilinx_bo_destroy(buf->bo);
err:
	free(buf);
#endif
	return NULL;
}

static void drm_gem_xilinx_free(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
#if 0
	struct xilinx_buffer *buf = (struct xilinx_buffer *)bo;

	UNUSED(drv);

	if (bo->handle && bo->handle->prime_fd)
		close(bo->handle->prime_fd);

	/* TODO: Is destroy correct here? */
	xilinx_bo_destroy(buf->bo);
	free(buf);
#endif
}

static int drm_gem_xilinx_map(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo, int x, int y, int w, int h,
		int enable_write, void **addr)
{
#if 0
	struct xilinx_buffer *buf = (struct xilinx_buffer *)bo;

	UNUSED(drv, x, y, w, h, enable_write);

	*addr = xilinx_bo_map(buf->bo);
	if (!*addr) {
		ALOGE("failed to map bo\n");
		return -1;
	}
#endif
	return 0;
}

static void drm_gem_xilinx_unmap(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	UNUSED(drv, bo);
}

struct gralloc_drm_drv_t *gralloc_drm_drv_create_for_xilinx(int fd)
{
	struct xilinx_info *info;
	int ret;

	info = (struct xilinx_info*)calloc(1, sizeof(*info));
	if (!info) {
		ALOGE("Failed to allocate xilinx gralloc device\n");
		return NULL;
	}

	info->xilinx = xilinx_device_create(fd);
	if (!info->xilinx) {
		ALOGE("Failed to create new xilinx instance\n");
		free(info);
		return NULL;
	}

	info->fd = fd;
	info->base.destroy = drm_gem_xilinx_destroy;
	info->base.alloc = drm_gem_xilinx_alloc;
	info->base.free = drm_gem_xilinx_free;
	info->base.map = drm_gem_xilinx_map;
	info->base.unmap = drm_gem_xilinx_unmap;

	return &info->base;
}
