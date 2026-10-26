package pcsconfig

import (
	"path/filepath"
	"testing"
)

// GetSavePath: no_user_dir=false 时保留 <uid>_<用户名> 这一层, true 时直接落在 savedir 下
func TestGetSavePathNoUserDir(t *testing.T) {
	oldSaveDir, oldNoUserDir := Config.SaveDir, Config.NoUserDir
	defer func() {
		Config.SaveDir, Config.NoUserDir = oldSaveDir, oldNoUserDir
	}()

	Config.SaveDir = "/data/downloads"
	baidu := &Baidu{
		BaiduBase: BaiduBase{
			UID:  1234,
			Name: "tester",
		},
	}

	Config.NoUserDir = false
	if got, want := baidu.GetSavePath("/电影/a.mkv"), filepath.Join("/data/downloads/1234_tester/电影/a.mkv"); got != want {
		t.Errorf("no_user_dir=false 保存路径错误: got %s, want %s", got, want)
	}

	Config.NoUserDir = true
	if got, want := baidu.GetSavePath("/电影/a.mkv"), filepath.Join("/data/downloads/电影/a.mkv"); got != want {
		t.Errorf("no_user_dir=true 保存路径错误: got %s, want %s", got, want)
	}

	// 根目录下的单个文件
	if got, want := baidu.GetSavePath("/a.jpg"), filepath.Join("/data/downloads/a.jpg"); got != want {
		t.Errorf("no_user_dir=true 根目录文件保存路径错误: got %s, want %s", got, want)
	}
}
