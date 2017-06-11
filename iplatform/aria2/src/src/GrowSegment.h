/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#ifndef D_GROW_SEGMENT_H
#define D_GROW_SEGMENT_H

#include "Segment.h"

namespace aria2 {

class GrowSegment:public Segment {
private:
  std::shared_ptr<Piece> piece_;
  int64_t writtenLength_;
public:
  GrowSegment(const std::shared_ptr<Piece>& piece);

  virtual ~GrowSegment();

  virtual bool complete() const CXX11_OVERRIDE
  {
    return false;
  }

  virtual size_t getIndex() const CXX11_OVERRIDE
  {
    return 0;
  }

  virtual int64_t getPosition() const CXX11_OVERRIDE
  {
    return 0;
  }

  virtual int64_t getPositionToWrite() const CXX11_OVERRIDE
  {
    return writtenLength_;
  }

  virtual int64_t getLength() const CXX11_OVERRIDE
  {
    return 0;
  }

  virtual int64_t getSegmentLength() const CXX11_OVERRIDE
  {
    return 0;
  }

  virtual int64_t getWrittenLength() const CXX11_OVERRIDE
  {
    return writtenLength_;
  }

  virtual void updateWrittenLength(int64_t bytes) CXX11_OVERRIDE;

  virtual bool updateHash
  (int64_t begin,
   const unsigned char* data,
   size_t dataLength) CXX11_OVERRIDE
  {
    return false;
  }

  virtual bool isHashCalculated() const CXX11_OVERRIDE
  {
    return false;
  }

  virtual std::string getDigest() CXX11_OVERRIDE;

  virtual void clear(WrDiskCache* diskCache) CXX11_OVERRIDE;

  virtual std::shared_ptr<Piece> getPiece() const CXX11_OVERRIDE;
};

} // namespace aria2

#endif // D_GROW_SEGMENT_H

