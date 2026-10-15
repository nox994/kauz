# Maintainer: nox994
pkgname=kauz
pkgver=0.3.0
pkgrel=1
pkgdesc="The friendly security check for your Linux PC"
arch=('any')
url="https://github.com/nox994/kauz"
license=('MIT')
depends=('python')
makedepends=('python-build' 'python-installer' 'python-setuptools' 'python-wheel')
optdepends=('pyside6: graphical interface (kauz-gui)')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('96da1f90876cadf46d74a5d1d7e56a06b252cb2cfc33f7b796bc4f30a6fa0a2c')

build() {
  cd "$pkgname-$pkgver"
  python -m build --wheel --no-isolation
}

package() {
  cd "$pkgname-$pkgver"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 data/kauz.desktop "$pkgdir/usr/share/applications/kauz.desktop"
  install -Dm644 data/kauz.svg "$pkgdir/usr/share/icons/hicolor/scalable/apps/kauz.svg"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
