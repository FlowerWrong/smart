package flowerwrong.github.com.smart.core;

import android.graphics.drawable.Drawable;

public class AppInfo {
    private Drawable appIcon;
    private String appLabel;
    private String pkgName;
    private boolean sys;

    public AppInfo() {
    }

    public Drawable getAppIcon() {
        return this.appIcon;
    }

    public String getAppLabel() {
        return this.appLabel;
    }

    public String getPkgName() {
        return this.pkgName;
    }

    public void setAppIcon(Drawable var1) {
        this.appIcon = var1;
    }

    public void setAppLabel(String var1) {
        this.appLabel = var1;
    }

    public void setPkgName(String var1) {
        this.pkgName = var1;
    }

    public boolean isSys() {
        return sys;
    }

    public void setSys(boolean sys) {
        this.sys = sys;
    }
}
