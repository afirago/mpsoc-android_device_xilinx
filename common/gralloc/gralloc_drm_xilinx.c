#include <cutils/log.h>
#include <stdlib.h>
#include <errno.h>
#include <drm.h>
#include <xilinx/xilinx_drmif.h>

#include "gralloc_priv.h"

#define UNUSED(...) (void)(__VA_ARGS__)

struct xilinx_info {
	struct gralloc_drm_drv_t base;

	struct xilinx_device *xilinx;
	int fd;
};

struct xilinx_buffer {
	struct gralloc_drm_bo_t base;

	struct xilinx_bo *bo;
};

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
